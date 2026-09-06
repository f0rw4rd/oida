"""
Tests for ReducedString primitive - optimized string fuzzing for protocols.

Tests cover:
- Fuzz library contents and reduction
- Long string seed expansion with boundary testing
- Reduction levels (balanced/aggressive)
- Statistics reporting
- Mutations output
"""

import pytest
from oida.fuzz.primitives.reduced_string import ReducedString


class TestReducedStringFuzzLibrary:
    """Test the static fuzz library contents."""

    def test_fuzz_library_is_list(self):
        assert isinstance(ReducedString._fuzz_library, list)
        assert len(ReducedString._fuzz_library) > 0

    def test_fuzz_library_has_empty_string(self):
        assert "" in ReducedString._fuzz_library

    def test_fuzz_library_has_null_bytes(self):
        has_null = any("\x00" in p or "%00" in p for p in ReducedString._fuzz_library)
        assert has_null, "Fuzz library should contain NULL byte payloads"

    def test_fuzz_library_has_crlf(self):
        has_crlf = any("\r\n" in p for p in ReducedString._fuzz_library)
        assert has_crlf, "Fuzz library should contain CRLF injection"

    def test_fuzz_library_has_binary(self):
        has_binary = any("\xde\xad\xbe\xef" in p for p in ReducedString._fuzz_library)
        assert has_binary, "Fuzz library should contain binary sequences"

    def test_fuzz_library_has_format_strings(self):
        has_fmt = any("%n" in p or "%s" in p or "%p" in p for p in ReducedString._fuzz_library)
        assert has_fmt, "Fuzz library should contain format string payloads"

    def test_fuzz_library_has_malformed_utf8(self):
        has_utf8 = any("\xc0\x80" in p or "\xed\xa0\x80" in p for p in ReducedString._fuzz_library)
        assert has_utf8, "Fuzz library should contain malformed UTF-8"

    def test_fuzz_library_no_command_injection(self):
        """Verify command injection payloads were removed."""
        for payload in ReducedString._fuzz_library:
            assert "$(reboot)" not in payload, "Should not have command injection"
            assert "|notepad" not in payload, "Should not have command injection"
            assert ";id" not in payload, "Should not have command injection"


class TestReducedStringSeeds:
    """Test long string seeds."""

    def test_seeds_has_null(self):
        assert "\x00" in ReducedString.long_string_seeds

    def test_seeds_has_max_byte(self):
        assert "\xff" in ReducedString.long_string_seeds

    def test_seeds_has_path_traversal(self):
        assert "../" in ReducedString.long_string_seeds
        assert "..\\" in ReducedString.long_string_seeds

    def test_seeds_has_format_strings(self):
        assert "%n" in ReducedString.long_string_seeds
        assert "%s" in ReducedString.long_string_seeds
        assert "%x" in ReducedString.long_string_seeds
        assert "%hhn" in ReducedString.long_string_seeds

    def test_seeds_has_protocol_delimiters(self):
        assert "\r" in ReducedString.long_string_seeds
        assert "\n" in ReducedString.long_string_seeds
        assert " " in ReducedString.long_string_seeds
        assert "." in ReducedString.long_string_seeds
        assert "/" in ReducedString.long_string_seeds


class TestReducedStringLengths:
    """Test length boundaries."""

    def test_lengths_are_powers_of_two(self):
        for length in ReducedString._long_string_lengths:
            # Check it's a power of 2 or a well-known size
            assert length in [8, 16, 32, 64, 128, 256, 512, 1024, 4096, 65535]

    def test_deltas_are_boundary_testing(self):
        assert -1 in ReducedString._long_string_deltas  # Off-by-one under
        assert 0 in ReducedString._long_string_deltas  # Exact
        assert 1 in ReducedString._long_string_deltas  # Off-by-one over

    def test_extra_long_disabled(self):
        """Extra long strings should be empty for protocol fuzzing speed."""
        assert ReducedString._extra_long_string_lengths == []


class TestReducedStringInstance:
    """Test instance creation and mutation generation."""

    def test_basic_creation(self):
        s = ReducedString(name="test", default_value="hello")
        assert s is not None

    def test_creation_with_max_len(self):
        s = ReducedString(name="test", default_value="hello", max_len=256)
        assert s is not None

    def test_mutations_are_generated(self):
        s = ReducedString(name="test", default_value="hello", max_len=256)
        mutations = list(s.mutations(b"hello"))
        assert len(mutations) > 0, "Should generate mutations"

    def test_mutations_include_fuzz_library(self):
        s = ReducedString(name="test", default_value="hello", max_len=65536)
        mutations = list(s.mutations(b"hello"))
        # Check some fuzz library payloads appear in mutations
        mutation_strs = set()
        for m in mutations:
            if isinstance(m, bytes):
                try:
                    mutation_strs.add(m.decode("utf-8"))
                except UnicodeDecodeError:
                    mutation_strs.add(m.decode("latin-1"))
            else:
                mutation_strs.add(m)
        assert "" in mutation_strs, "Should include empty string"

    def test_mutations_include_length_boundaries(self):
        s = ReducedString(name="test", default_value="A", max_len=65536)
        mutations = list(s.mutations(b"A"))
        lengths = sorted(set(len(m) if isinstance(m, (str, bytes)) else 0 for m in mutations))
        # Should have various lengths from seed expansion
        assert max(lengths) > 100, f"Should have long mutations, max was {max(lengths)}"

    def test_mutations_respect_max_len(self):
        max_len = 256
        s = ReducedString(name="test", default_value="A", max_len=max_len)
        mutations = list(s.mutations(b"A"))
        for m in mutations:
            if isinstance(m, (str, bytes)):
                assert len(m) <= max_len + 1, f"Mutation length {len(m)} exceeds max_len {max_len}"

    def test_num_mutations(self):
        s = ReducedString(name="test", default_value="hello")
        count = s.num_mutations(b"hello")
        assert count > 0, "Should report positive mutation count"

    def test_mutation_count_much_less_than_original(self):
        """ReducedString should have significantly fewer mutations than boofuzz String."""
        s = ReducedString(name="test", default_value="hello", max_len=65536)
        count = s.num_mutations(b"hello")
        # Original boofuzz String has ~1800 mutations, reduced should be ~300
        assert count < 1000, f"Should be reduced, got {count}"


class TestReductionLevels:
    """Test reduction level switching."""

    _original_fuzz_library = None
    _original_seeds = None
    _original_lengths = None
    _original_deltas = None

    def setup_method(self):
        """Save originals before each test."""
        self._original_fuzz_library = list(ReducedString._fuzz_library)
        self._original_seeds = list(ReducedString.long_string_seeds)
        self._original_lengths = list(ReducedString._long_string_lengths)
        self._original_deltas = list(ReducedString._long_string_deltas)

    def teardown_method(self):
        """Restore originals after each test."""
        ReducedString._fuzz_library = self._original_fuzz_library
        ReducedString.long_string_seeds = self._original_seeds
        ReducedString._long_string_lengths = self._original_lengths
        ReducedString._long_string_deltas = self._original_deltas
        ReducedString.reduction_level = "balanced"

    def test_default_is_balanced(self):
        assert ReducedString.reduction_level == "balanced"

    def test_set_aggressive(self):
        ReducedString.set_reduction_level("aggressive")
        assert ReducedString.reduction_level == "aggressive"
        assert len(ReducedString._fuzz_library) < len(self._original_fuzz_library)
        assert len(ReducedString.long_string_seeds) < len(self._original_seeds)

    def test_aggressive_has_fewer_mutations(self):
        balanced_stats = ReducedString.get_stats()
        ReducedString.set_reduction_level("aggressive")
        aggressive_stats = ReducedString.get_stats()
        assert aggressive_stats["total_per_field"] < balanced_stats["total_per_field"]

    def test_aggressive_still_has_essentials(self):
        ReducedString.set_reduction_level("aggressive")
        assert "" in ReducedString._fuzz_library
        assert "%00" in ReducedString._fuzz_library
        # Seeds should still have path traversal and format strings
        assert "../" in ReducedString.long_string_seeds
        assert "%n" in ReducedString.long_string_seeds

    def test_switch_back_to_balanced(self):
        ReducedString.set_reduction_level("aggressive")
        ReducedString.set_reduction_level("balanced")
        assert ReducedString.reduction_level == "balanced"

    def test_invalid_level_raises(self):
        with pytest.raises(ValueError, match="Unknown reduction level"):
            ReducedString.set_reduction_level("turbo")


class TestReducedStringStats:
    """Test statistics reporting."""

    def test_get_stats(self):
        stats = ReducedString.get_stats()
        assert "reduction_level" in stats
        assert "fuzz_library_count" in stats
        assert "long_string_count" in stats
        assert "total_per_field" in stats
        assert stats["total_per_field"] == stats["fuzz_library_count"] + stats["long_string_count"]

    def test_stats_mutation_count_reduced(self):
        stats = ReducedString.get_stats()
        # Should be significantly less than original boofuzz (~1800)
        assert stats["total_per_field"] < 1000
        # But still meaningful (at least 100)
        assert stats["total_per_field"] > 100
