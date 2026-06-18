"""
Tests for the native Python radamsa mutation implementation.

Tests cover:
- NativeRadamsaMutator: Core mutation class
- All 25 mutation types
- Determinism and reproducibility
- Edge cases (empty data, binary data, etc.)
"""

import pytest
from src.oida.fuzz.core.mutation.radamsa_native import (
    NativeRadamsaMutator,
    get_native_mutator,
    INTERESTING_8,
    INTERESTING_16,
    INTERESTING_32,
    ASCII_NUMBERS,
)


# =============================================================================
# Test NativeRadamsaMutator Initialization
# =============================================================================


class TestNativeRadamsaMutatorInit:
    """Tests for NativeRadamsaMutator initialization."""

    def test_init_without_seed(self):
        """NativeRadamsaMutator can be created without seed."""
        mutator = NativeRadamsaMutator()
        assert mutator is not None
        assert mutator.rng is not None

    def test_init_with_seed(self):
        """NativeRadamsaMutator can be created with seed."""
        mutator = NativeRadamsaMutator(seed=42)
        assert mutator is not None

    def test_set_seed(self):
        """Seed can be changed after creation."""
        mutator = NativeRadamsaMutator(seed=1)
        mutator.set_seed(42)
        # Verify by generating mutations
        result1 = mutator.mutate(b"test")
        mutator.set_seed(42)
        result2 = mutator.mutate(b"test")
        assert result1 == result2


class TestNativeRadamsaMutatorSamples:
    """Tests for sample management."""

    def test_add_sample(self):
        """Samples can be added."""
        mutator = NativeRadamsaMutator()
        mutator.add_sample(b"sample1")
        mutator.add_sample(b"sample2")
        assert len(mutator._samples) == 2

    def test_clear_samples(self):
        """Samples can be cleared."""
        mutator = NativeRadamsaMutator()
        mutator.add_sample(b"sample1")
        mutator.clear_samples()
        assert len(mutator._samples) == 0


# =============================================================================
# Test Core Mutation Methods
# =============================================================================


class TestMutate:
    """Tests for the main mutate() method."""

    def test_mutate_returns_bytes(self):
        """mutate() returns bytes."""
        mutator = NativeRadamsaMutator(seed=42)
        result = mutator.mutate(b"test data")
        assert isinstance(result, bytes)

    def test_mutate_modifies_data(self):
        """mutate() usually changes the data."""
        mutator = NativeRadamsaMutator(seed=42)
        original = b"test data for mutation"
        # Try multiple mutations - at least one should differ
        different = False
        for i in range(10):
            result = mutator.mutate(original, seed=i)
            if result != original:
                different = True
                break
        assert different, "Mutations should modify data"

    def test_mutate_deterministic_with_seed(self):
        """Same seed produces same mutation."""
        mutator = NativeRadamsaMutator()
        result1 = mutator.mutate(b"test", seed=123)
        result2 = mutator.mutate(b"test", seed=123)
        assert result1 == result2

    def test_mutate_different_seeds_different_results(self):
        """Different seeds usually produce different mutations."""
        mutator = NativeRadamsaMutator()
        results = set()
        for seed in range(20):
            result = mutator.mutate(b"test data here", seed=seed)
            results.add(result)
        # Should have multiple unique results
        assert len(results) > 5, "Different seeds should produce variety"

    def test_mutate_empty_data(self):
        """Empty data generates some output."""
        mutator = NativeRadamsaMutator(seed=42)
        result = mutator.mutate(b"")
        assert isinstance(result, bytes)
        assert len(result) > 0


class TestMutateBatch:
    """Tests for batch mutation."""

    def test_mutate_batch_returns_list(self):
        """mutate_batch() returns a list."""
        mutator = NativeRadamsaMutator(seed=42)
        result = mutator.mutate_batch(b"test", count=5)
        assert isinstance(result, list)
        assert len(result) == 5

    def test_mutate_batch_correct_count(self):
        """mutate_batch() generates correct number of mutations."""
        mutator = NativeRadamsaMutator(seed=42)
        result = mutator.mutate_batch(b"test", count=100)
        assert len(result) == 100

    def test_mutate_batch_reproducible(self):
        """mutate_batch() is reproducible with same start_seed."""
        mutator1 = NativeRadamsaMutator()
        mutator2 = NativeRadamsaMutator()
        result1 = mutator1.mutate_batch(b"test", count=5, start_seed=10)
        result2 = mutator2.mutate_batch(b"test", count=5, start_seed=10)
        assert result1 == result2


# =============================================================================
# Test Byte-Level Mutations
# =============================================================================


class TestByteLevelMutations:
    """Tests for byte-level mutation operations."""

    @pytest.fixture
    def mutator(self):
        return NativeRadamsaMutator(seed=42)

    def test_byte_drop(self, mutator):
        """byte_drop removes bytes."""
        original = b"ABCDEFGHIJ"
        result = mutator.byte_drop(original)
        assert len(result) < len(original)
        assert isinstance(result, bytes)

    def test_byte_drop_preserves_some_data(self, mutator):
        """byte_drop doesn't remove all data."""
        original = b"ABCDEFGHIJ"
        result = mutator.byte_drop(original)
        assert len(result) >= 1

    def test_byte_flip(self, mutator):
        """byte_flip changes bits."""
        original = b"AAAAAAAAAA"
        result = mutator.byte_flip(original)
        assert result != original
        assert len(result) == len(original)

    def test_byte_insert(self, mutator):
        """byte_insert adds bytes."""
        original = b"ABCD"
        result = mutator.byte_insert(original)
        assert len(result) > len(original)

    def test_byte_repeat(self, mutator):
        """byte_repeat duplicates byte sequences."""
        original = b"ABCD"
        result = mutator.byte_repeat(original)
        assert len(result) > len(original)

    def test_byte_permute(self, mutator):
        """byte_permute shuffles bytes."""
        original = b"ABCDEFGHIJ"
        result = mutator.byte_permute(original)
        assert len(result) == len(original)
        # Should have same bytes, possibly reordered
        assert sorted(result) == sorted(original) or result != original

    def test_byte_inc(self, mutator):
        """byte_inc increments bytes."""
        original = b"\x00\x00\x00\x00"
        result = mutator.byte_inc(original)
        assert result != original
        assert len(result) == len(original)

    def test_byte_dec(self, mutator):
        """byte_dec decrements bytes."""
        original = b"\xff\xff\xff\xff"
        result = mutator.byte_dec(original)
        assert result != original
        assert len(result) == len(original)

    def test_byte_random(self, mutator):
        """byte_random replaces with random values."""
        original = b"\x00" * 20
        result = mutator.byte_random(original)
        assert len(result) == len(original)
        # At least some bytes should be different
        assert result != original

    def test_seq_repeat(self, mutator):
        """seq_repeat duplicates larger sequences."""
        original = b"ABCDEFGHIJKLMNOP"
        result = mutator.seq_repeat(original)
        assert len(result) > len(original)

    def test_seq_delete(self, mutator):
        """seq_delete removes byte ranges."""
        original = b"A" * 100
        result = mutator.seq_delete(original)
        assert len(result) < len(original)


class TestByteMutationsEdgeCases:
    """Edge case tests for byte mutations."""

    @pytest.fixture
    def mutator(self):
        return NativeRadamsaMutator(seed=42)

    def test_byte_drop_single_byte(self, mutator):
        """byte_drop handles single byte input."""
        result = mutator.byte_drop(b"A")
        assert isinstance(result, bytes)

    def test_byte_flip_single_byte(self, mutator):
        """byte_flip handles single byte input."""
        result = mutator.byte_flip(b"A")
        assert isinstance(result, bytes)
        assert len(result) == 1

    def test_byte_permute_two_bytes(self, mutator):
        """byte_permute handles two byte input."""
        result = mutator.byte_permute(b"AB")
        assert len(result) == 2

    def test_mutations_handle_empty_data(self, mutator):
        """Byte mutations handle empty data gracefully."""
        empty = b""
        # These should not raise
        assert mutator.byte_drop(empty) == empty
        assert mutator.byte_flip(empty) == empty
        assert len(mutator.byte_insert(empty)) > 0


# =============================================================================
# Test Line-Level Mutations
# =============================================================================


class TestLineLevelMutations:
    """Tests for line-level mutation operations."""

    @pytest.fixture
    def mutator(self):
        return NativeRadamsaMutator(seed=42)

    @pytest.fixture
    def multiline_data(self):
        return b"line1\nline2\nline3\nline4\nline5\n"

    def test_line_delete(self, mutator, multiline_data):
        """line_delete removes lines."""
        result = mutator.line_delete(multiline_data)
        original_lines = multiline_data.count(b"\n")
        result_lines = result.count(b"\n")
        assert result_lines < original_lines

    def test_line_duplicate(self, mutator, multiline_data):
        """line_duplicate copies lines."""
        result = mutator.line_duplicate(multiline_data)
        assert len(result) > len(multiline_data)

    def test_line_clone(self, mutator, multiline_data):
        """line_clone copies line to different position."""
        result = mutator.line_clone(multiline_data)
        assert len(result) > len(multiline_data)

    def test_line_repeat(self, mutator, multiline_data):
        """line_repeat duplicates a line many times."""
        result = mutator.line_repeat(multiline_data)
        assert len(result) > len(multiline_data)

    def test_line_swap(self, mutator, multiline_data):
        """line_swap exchanges two lines."""
        result = mutator.line_swap(multiline_data)
        assert len(result) == len(multiline_data)

    def test_line_permute(self, mutator, multiline_data):
        """line_permute shuffles all lines."""
        result = mutator.line_permute(multiline_data)
        # Same length, same lines, different order (usually)
        assert len(result) == len(multiline_data)

    def test_line_insert(self, mutator, multiline_data):
        """line_insert adds a mutated line."""
        result = mutator.line_insert(multiline_data)
        assert len(result) > len(multiline_data)

    def test_line_replace(self, mutator, multiline_data):
        """line_replace replaces a line with mutated version."""
        result = mutator.line_replace(multiline_data)
        # May be same length or slightly different
        assert isinstance(result, bytes)


class TestLineMutationsEdgeCases:
    """Edge case tests for line mutations."""

    @pytest.fixture
    def mutator(self):
        return NativeRadamsaMutator(seed=42)

    def test_single_line_data(self, mutator):
        """Line mutations handle single-line data."""
        single_line = b"no newlines here"
        result = mutator.line_delete(single_line)
        assert isinstance(result, bytes)

    def test_crlf_line_endings(self, mutator):
        """Line mutations handle CRLF endings."""
        crlf_data = b"line1\r\nline2\r\nline3\r\n"
        result = mutator.line_duplicate(crlf_data)
        assert b"\r\n" in result

    def test_cr_only_line_endings(self, mutator):
        """Line mutations handle CR-only endings."""
        cr_data = b"line1\rline2\rline3\r"
        result = mutator.line_swap(cr_data)
        assert isinstance(result, bytes)

    def test_empty_lines(self, mutator):
        """Line mutations handle empty lines."""
        with_empty = b"line1\n\nline3\n"
        result = mutator.line_duplicate(with_empty)
        assert isinstance(result, bytes)


# =============================================================================
# Test Fusion Mutations
# =============================================================================


class TestFusionMutations:
    """Tests for fusion mutation operations."""

    @pytest.fixture
    def mutator(self):
        return NativeRadamsaMutator(seed=42)

    def test_fuse_self(self, mutator):
        """fuse_self combines data with itself."""
        original = b"A" * 20 + b"B" * 20 + b"C" * 20
        result = mutator.fuse_self(original)
        assert isinstance(result, bytes)
        assert len(result) != len(original) or result != original

    def test_fuse_samples_without_samples(self, mutator):
        """fuse_samples falls back to fuse_self without samples."""
        original = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        result = mutator.fuse_samples(original)
        assert isinstance(result, bytes)

    def test_fuse_samples_with_samples(self, mutator):
        """fuse_samples uses stored samples."""
        mutator.add_sample(b"SAMPLE_DATA_12345678")
        original = b"ORIGINAL_DATA_87654321"
        result = mutator.fuse_samples(original)
        assert isinstance(result, bytes)

    def test_fuse_short_data(self, mutator):
        """Fusion handles short data gracefully."""
        short = b"AB"
        result = mutator.fuse_self(short)
        assert isinstance(result, bytes)


# =============================================================================
# Test Special Mutations
# =============================================================================


class TestSpecialMutations:
    """Tests for special mutation operations."""

    @pytest.fixture
    def mutator(self):
        return NativeRadamsaMutator(seed=42)

    def test_num_mutate_decimal(self, mutator):
        """num_mutate modifies decimal numbers."""
        original = b"value=123 count=456"
        result = mutator.num_mutate(original)
        assert isinstance(result, bytes)
        # Number should be different
        assert result != original or b"123" not in result or b"456" not in result

    def test_num_mutate_hex(self, mutator):
        """num_mutate modifies hex numbers."""
        original = b"address=0x1234 size=0xFF"
        result = mutator.num_mutate(original)
        assert isinstance(result, bytes)

    def test_num_mutate_no_numbers(self, mutator):
        """num_mutate falls back when no numbers present."""
        original = b"no numbers here"
        result = mutator.num_mutate(original)
        assert isinstance(result, bytes)

    def test_interesting_bytes(self, mutator):
        """interesting_bytes inserts boundary values."""
        original = b"AAAAAAAAAA"
        result = mutator.interesting_bytes(original)
        assert isinstance(result, bytes)

    def test_utf8_widen(self, mutator):
        """utf8_widen creates overlong UTF-8 sequences."""
        original = b"Hello World"
        result = mutator.utf8_widen(original)
        assert isinstance(result, bytes)
        # Should be longer due to multi-byte encoding
        assert len(result) > len(original)

    def test_utf8_widen_no_ascii(self, mutator):
        """utf8_widen handles non-ASCII data."""
        original = b"\x00\x01\x02\x03"
        result = mutator.utf8_widen(original)
        assert isinstance(result, bytes)

    def test_ascii_num_insert(self, mutator):
        """ascii_num_insert adds number strings."""
        original = b"data"
        result = mutator.ascii_num_insert(original)
        assert len(result) > len(original)
        # Should contain one of the ASCII number patterns
        has_number = any(num in result for num in ASCII_NUMBERS)
        assert has_number

    def test_chunk_swap(self, mutator):
        """chunk_swap exchanges data chunks."""
        original = b"AAAA" + b"BBBB" + b"CCCC" + b"DDDD"
        result = mutator.chunk_swap(original)
        assert len(result) == len(original)


# =============================================================================
# Test Utility Methods
# =============================================================================


class TestUtilityMethods:
    """Tests for utility methods."""

    def test_get_mutation_names(self):
        """get_mutation_names returns all mutation names."""
        mutator = NativeRadamsaMutator()
        names = mutator.get_mutation_names()
        assert len(names) >= 24  # At least 24 mutations
        assert "byte_flip" in names
        assert "line_delete" in names
        assert "fuse_self" in names

    def test_apply_mutation_valid(self):
        """apply_mutation applies specific mutation by name."""
        mutator = NativeRadamsaMutator(seed=42)
        result = mutator.apply_mutation("byte_flip", b"test data")
        assert isinstance(result, bytes)

    def test_apply_mutation_invalid(self):
        """apply_mutation raises for unknown mutation."""
        mutator = NativeRadamsaMutator()
        with pytest.raises(ValueError, match="Unknown mutation"):
            mutator.apply_mutation("nonexistent_mutation", b"test")


# =============================================================================
# Test Factory Function
# =============================================================================


class TestFactoryFunction:
    """Tests for get_native_mutator factory."""

    def test_get_native_mutator_default(self):
        """get_native_mutator creates mutator without seed."""
        mutator = get_native_mutator()
        assert isinstance(mutator, NativeRadamsaMutator)

    def test_get_native_mutator_with_seed(self):
        """get_native_mutator creates mutator with seed."""
        mutator = get_native_mutator(seed=42)
        assert isinstance(mutator, NativeRadamsaMutator)


# =============================================================================
# Test Constants
# =============================================================================


class TestConstants:
    """Tests for exported constants."""

    def test_interesting_8_values(self):
        """INTERESTING_8 contains expected boundary values."""
        assert 0 in INTERESTING_8
        assert 127 in INTERESTING_8
        assert 128 in INTERESTING_8
        assert 255 in INTERESTING_8

    def test_interesting_16_values(self):
        """INTERESTING_16 contains expected boundary values."""
        assert 0 in INTERESTING_16
        assert 32767 in INTERESTING_16
        assert 32768 in INTERESTING_16
        assert 65535 in INTERESTING_16

    def test_interesting_32_values(self):
        """INTERESTING_32 contains expected boundary values."""
        assert 0 in INTERESTING_32
        assert 0x7FFFFFFF in INTERESTING_32
        assert 0xFFFFFFFF in INTERESTING_32

    def test_ascii_numbers_contains_boundaries(self):
        """ASCII_NUMBERS contains important boundary strings."""
        assert b"0" in ASCII_NUMBERS
        assert b"-1" in ASCII_NUMBERS
        assert b"2147483647" in ASCII_NUMBERS
        assert b"NaN" in ASCII_NUMBERS


# =============================================================================
# Test Integration with Protocol Data
# =============================================================================


class TestProtocolIntegration:
    """Tests for protocol fuzzing integration."""

    @pytest.fixture
    def mutator(self):
        return NativeRadamsaMutator(seed=42)

    def test_modbus_pdu_mutation(self, mutator):
        """Modbus PDU can be mutated."""
        modbus_pdu = b"\x01\x03\x00\x00\x00\x01"  # Read holding registers
        result = mutator.mutate(modbus_pdu)
        assert isinstance(result, bytes)

    def test_http_request_mutation(self, mutator):
        """HTTP request can be mutated."""
        http_request = b"GET / HTTP/1.1\r\nHost: test.com\r\n\r\n"
        result = mutator.mutate(http_request)
        assert isinstance(result, bytes)

    def test_binary_all_bytes(self, mutator):
        """All byte values can be mutated."""
        all_bytes = bytes(range(256))
        result = mutator.mutate(all_bytes)
        assert isinstance(result, bytes)

    def test_batch_protocol_mutations(self, mutator):
        """Batch mutations work for protocol data."""
        modbus_pdu = b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x0a"
        results = mutator.mutate_batch(modbus_pdu, count=50)
        assert len(results) == 50
        # Should have variety
        unique_results = set(results)
        assert len(unique_results) > 10


# =============================================================================
# Test Edge Cases
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    @pytest.fixture
    def mutator(self):
        return NativeRadamsaMutator(seed=42)

    def test_very_long_data(self, mutator):
        """Long data can be mutated."""
        long_data = b"A" * 100000
        result = mutator.mutate(long_data)
        assert isinstance(result, bytes)

    def test_single_byte_data(self, mutator):
        """Single byte data can be mutated."""
        single = b"X"
        result = mutator.mutate(single)
        assert isinstance(result, bytes)

    def test_null_bytes(self, mutator):
        """Data with null bytes can be mutated."""
        with_nulls = b"data\x00with\x00nulls"
        result = mutator.mutate(with_nulls)
        assert isinstance(result, bytes)

    def test_high_entropy_data(self, mutator):
        """Random-looking data can be mutated."""
        import os

        random_data = os.urandom(100)
        result = mutator.mutate(random_data)
        assert isinstance(result, bytes)

    def test_repeated_mutations(self, mutator):
        """Many consecutive mutations work correctly."""
        data = b"initial data"
        for _ in range(100):
            data = mutator.mutate(data)
        assert isinstance(data, bytes)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
