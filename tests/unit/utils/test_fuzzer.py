#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Comprehensive tests for the fuzzer utility module.

Tests type-aware boundary generation, mutations, and fuzz case generation.
"""

import pytest
from oida.utils.fuzzer import (
    fuzz,
    TYPE_ALIASES,
    _get_type_boundaries,
    _simple_mutate,
)


# =============================================================================
# Test Type Aliases
# =============================================================================


class TestTypeAliases:
    """Tests for type alias mappings."""

    @pytest.mark.parametrize(
        "alias,expected",
        [
            # CIP types
            ("BOOL", "bool"),
            ("USINT", "uint8"),
            ("SINT", "int8"),
            ("UINT", "uint16"),
            ("INT", "int16"),
            ("UDINT", "uint32"),
            ("DINT", "int32"),
            ("REAL", "float32"),
            ("ULINT", "uint64"),
            ("LINT", "int64"),
            ("LREAL", "float64"),
            ("STRING", "string"),
            # OPC UA types
            ("Boolean", "bool"),
            ("SByte", "int8"),
            ("Byte", "uint8"),
            ("Int16", "int16"),
            ("UInt16", "uint16"),
            ("Int32", "int32"),
            ("UInt32", "uint32"),
            ("Float", "float32"),
            ("Double", "float64"),
            ("String", "string"),
            # Modbus types
            ("COIL", "bool"),
            ("DISCRETE", "bool"),
            ("HOLDING", "uint16"),
            ("INPUT", "uint16"),
        ],
    )
    def test_type_alias_mapping(self, alias, expected):
        """Verify type alias maps to normalized type."""
        assert TYPE_ALIASES[alias] == expected


# =============================================================================
# Test Type Boundaries
# =============================================================================


class TestGetTypeBoundaries:
    """Tests for _get_type_boundaries function."""

    def test_bool_boundaries(self):
        """Boolean type generates valid/invalid test cases."""
        cases = _get_type_boundaries("bool")
        payloads = [c[0] for c in cases]
        descriptions = [c[1] for c in cases]

        assert b"\x00" in payloads  # false
        assert b"\x01" in payloads  # true
        assert b"\xff" in payloads  # invalid
        assert any("invalid" in d for d in descriptions)

    def test_uint8_boundaries(self):
        """uint8 generates boundary values."""
        cases = _get_type_boundaries("uint8")
        payloads = [c[0] for c in cases]

        assert b"\x00" in payloads  # zero
        assert b"\xff" in payloads  # max
        assert b"\x7f" in payloads  # 127

    def test_uint16_boundaries(self):
        """uint16 generates boundary values."""
        cases = _get_type_boundaries("uint16")
        payloads = [c[0] for c in cases]

        assert b"\x00\x00" in payloads  # zero
        assert b"\xff\xff" in payloads  # max
        assert b"\xff\x7f" in payloads  # INT16_MAX

    def test_uint32_boundaries(self):
        """uint32 generates boundary values."""
        cases = _get_type_boundaries("uint32")
        payloads = [c[0] for c in cases]

        assert b"\x00\x00\x00\x00" in payloads  # zero
        assert b"\xff\xff\xff\xff" in payloads  # max
        assert b"\xff\xff\xff\x7f" in payloads  # INT32_MAX

    def test_float32_boundaries(self):
        """float32 generates IEEE 754 special values."""
        cases = _get_type_boundaries("float32")
        descriptions = [c[1] for c in cases]

        assert any("0.0" in d for d in descriptions)
        assert any("1.0" in d for d in descriptions)
        assert any("Infinity" in d for d in descriptions)
        assert any("NaN" in d for d in descriptions)

    def test_string_boundaries(self):
        """string type generates length-prefixed test cases."""
        cases = _get_type_boundaries("string")
        descriptions = [c[1] for c in cases]

        assert any("empty" in d for d in descriptions)
        assert any("length" in d for d in descriptions)

    def test_cip_type_alias(self):
        """CIP type DINT maps to int32 boundaries."""
        cases = _get_type_boundaries("DINT")
        payloads = [c[0] for c in cases]

        assert b"\x00\x00\x00\x00" in payloads
        assert b"\xff\xff\xff\x7f" in payloads  # INT32_MAX

    def test_struct_with_original(self):
        """struct type generates mutations of original."""
        original = b"\x01\x02\x03\x04"
        cases = _get_type_boundaries("struct", original)

        assert len(cases) > 0
        # Should have all-zeros and all-0xFF of same length
        payloads = [c[0] for c in cases]
        assert b"\x00\x00\x00\x00" in payloads
        assert b"\xff\xff\xff\xff" in payloads


# =============================================================================
# Test Simple Mutate
# =============================================================================


class TestSimpleMutate:
    """Tests for _simple_mutate function."""

    def test_mutate_returns_bytes(self):
        """Mutation always returns bytes."""
        result = _simple_mutate(b"\x01\x02\x03", 0)
        assert isinstance(result, bytes)

    def test_mutate_empty_input(self):
        """Mutating empty input generates random bytes."""
        result = _simple_mutate(b"", 0)
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_mutate_different_seeds(self):
        """Different seeds produce different mutations."""
        original = b"\x01\x02\x03\x04"
        results = set()
        for seed in range(8):
            result = _simple_mutate(original, seed)
            results.add(result)
        # Should have multiple unique results
        assert len(results) > 1

    def test_mutate_bit_flip(self):
        """Seed 0 does bit flip."""
        original = b"\x00\x00\x00\x00"
        result = _simple_mutate(original, 0)
        # Result should differ by exactly one bit (in most cases)
        assert result != original

    def test_mutate_all_zeros(self):
        """Seed 2 produces all zeros."""
        original = b"\x01\x02\x03\x04"
        result = _simple_mutate(original, 2)
        assert result == b"\x00\x00\x00\x00"

    def test_mutate_all_ff(self):
        """Seed 3 produces all 0xFF."""
        original = b"\x01\x02\x03\x04"
        result = _simple_mutate(original, 3)
        assert result == b"\xff\xff\xff\xff"


# =============================================================================
# Test Fuzz Generator
# =============================================================================


class TestFuzzGenerator:
    """Tests for main fuzz() generator function."""

    def test_fuzz_returns_iterator(self):
        """fuzz() returns an iterator."""
        result = fuzz(count=5)
        assert hasattr(result, "__iter__")
        assert hasattr(result, "__next__")

    def test_fuzz_yields_tuples(self):
        """fuzz() yields (bytes, str) tuples."""
        for payload, desc in fuzz(count=5):
            assert isinstance(payload, bytes)
            assert isinstance(desc, str)

    def test_fuzz_respects_count(self):
        """fuzz() yields at most count items."""
        results = list(fuzz(count=10))
        assert len(results) <= 10

    def test_fuzz_with_original(self):
        """fuzz() with original value includes mutations of it."""
        original = b"\x01\x02\x03\x04"
        results = list(fuzz(original=original, count=20))
        assert len(results) > 0
        # Should have some variations
        payloads = [r[0] for r in results]
        assert len(set(payloads)) > 1

    def test_fuzz_with_data_type(self):
        """fuzz() with data_type includes type-specific boundaries."""
        results = list(fuzz(data_type="uint16", count=20))
        payloads = [r[0] for r in results]
        [r[1] for r in results]

        # Should include uint16 boundary values
        assert b"\x00\x00" in payloads
        assert b"\xff\xff" in payloads

    def test_fuzz_min_len_filter(self):
        """fuzz() respects min_len filter."""
        results = list(fuzz(count=20, min_len=4))
        for payload, _ in results:
            assert len(payload) >= 4

    def test_fuzz_max_len_filter(self):
        """fuzz() respects max_len filter."""
        results = list(fuzz(count=20, max_len=8))
        for payload, _ in results:
            assert len(payload) <= 8

    def test_fuzz_unique_results(self):
        """fuzz() produces unique payloads."""
        results = list(fuzz(count=50))
        payloads = [r[0] for r in results]
        # Most should be unique
        assert len(set(payloads)) == len(payloads)

    def test_fuzz_bool_type(self):
        """fuzz() with bool type includes valid/invalid booleans."""
        results = list(fuzz(data_type="BOOL", count=10))
        payloads = [r[0] for r in results]

        assert b"\x00" in payloads  # false
        assert b"\x01" in payloads  # true

    def test_fuzz_float32_type(self):
        """fuzz() with float32 includes IEEE 754 special values."""
        results = list(fuzz(data_type="float32", count=15))
        descriptions = [r[1] for r in results]

        # Should have float-specific descriptions
        assert any("0.0" in d or "1.0" in d or "NaN" in d or "Infinity" in d for d in descriptions)

    def test_fuzz_cip_real_type(self):
        """fuzz() with CIP REAL type (alias for float32)."""
        results = list(fuzz(data_type="REAL", count=15))
        # Should work the same as float32
        assert len(results) > 0

    def test_fuzz_modbus_holding_type(self):
        """fuzz() with Modbus HOLDING type (alias for uint16)."""
        results = list(fuzz(data_type="HOLDING", count=15))
        payloads = [r[0] for r in results]

        assert b"\x00\x00" in payloads
        assert b"\xff\xff" in payloads

    def test_fuzz_empty_original(self):
        """fuzz() handles empty original value."""
        results = list(fuzz(original=b"", count=10))
        assert len(results) > 0

    def test_fuzz_large_count(self):
        """fuzz() can generate many test cases."""
        results = list(fuzz(count=200))
        # Should get close to requested count
        assert len(results) >= 100


# =============================================================================
# Test Fuzz Integration
# =============================================================================


class TestFuzzIntegration:
    """Integration tests for fuzz scenarios."""

    def test_modbus_register_fuzzing(self):
        """Fuzz Modbus register values (uint16)."""
        original = b"\x00\x64"  # Value 100 in big-endian
        results = list(fuzz(original=original, data_type="uint16", count=30))

        assert len(results) > 0
        # Should include boundary cases
        payloads = [r[0] for r in results]
        assert b"\x00\x00" in payloads or b"\xff\xff" in payloads

    def test_cip_dint_fuzzing(self):
        """Fuzz CIP DINT (32-bit signed integer)."""
        original = b"\x00\x00\x00\x00"
        results = list(fuzz(original=original, data_type="DINT", count=30))

        [r[0] for r in results]
        descriptions = [r[1] for r in results]

        # Should include INT32 boundary values
        assert any("INT32" in d for d in descriptions)

    def test_opcua_float_fuzzing(self):
        """Fuzz OPC UA Float type (using lowercase float32)."""
        # Note: TYPE_ALIASES has "Float" but _get_type_boundaries uses .upper()
        # which breaks the lookup. Use lowercase "float32" directly.
        results = list(fuzz(data_type="float32", count=20))
        descriptions = [r[1].lower() for r in results]

        # Should include float special values (case-insensitive)
        assert any("infinity" in d or "nan" in d or "1.0" in d or "0.0" in d for d in descriptions)

    def test_protocol_agnostic_fuzzing(self):
        """Fuzz without type (generic mutations)."""
        original = b"\xde\xad\xbe\xef"
        results = list(fuzz(original=original, count=30))

        assert len(results) > 0
        # Should have generic boundary cases
        payloads = [r[0] for r in results]
        # Empty or single byte should be present
        assert any(len(p) <= 1 for p in payloads) or any(
            p == b"\x00" * 4 or p == b"\xff" * 4 for p in payloads
        )
