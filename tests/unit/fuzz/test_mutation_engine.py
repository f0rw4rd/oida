"""
Tests for the Radamsa mutation engine.

Tests cover:
- RadamsaMutator: Core mutation class
- SeedLoader: Seed loading utilities
- Mutation determinism and reproducibility
- Batch and streaming mutation generation
- Error handling
"""

import pytest
import tempfile
import os
import sys
from unittest.mock import MagicMock


# =============================================================================
# Fixtures for mocking pyradamsa
# =============================================================================


@pytest.fixture
def mock_pyradamsa():
    """Create a mock pyradamsa module and inject it into sys.modules."""
    mock_radamsa_instance = MagicMock()
    mock_radamsa_instance.fuzz.return_value = b"mutated_data"

    mock_module = MagicMock()
    mock_module.Radamsa.return_value = mock_radamsa_instance

    # Store original if it exists
    original = sys.modules.get("pyradamsa")

    # Inject mock
    sys.modules["pyradamsa"] = mock_module

    # Clear any cached imports of RadamsaMutator
    if "src.oida.fuzz.core.mutation.radamsa" in sys.modules:
        del sys.modules["src.oida.fuzz.core.mutation.radamsa"]

    yield mock_module, mock_radamsa_instance

    # Restore original
    if original is not None:
        sys.modules["pyradamsa"] = original
    elif "pyradamsa" in sys.modules:
        del sys.modules["pyradamsa"]

    # Clear cached import
    if "src.oida.fuzz.core.mutation.radamsa" in sys.modules:
        del sys.modules["src.oida.fuzz.core.mutation.radamsa"]


# =============================================================================
# Test RadamsaMutator Initialization
# =============================================================================


class TestRadamsaMutatorInit:
    """Tests for RadamsaMutator initialization."""

    def test_init_without_seeds(self, mock_pyradamsa):
        """RadamsaMutator can be created without seeds."""
        mock_module, mock_instance = mock_pyradamsa
        from src.oida.fuzz.core.mutation.radamsa import RadamsaMutator

        mutator = RadamsaMutator()
        assert mutator.seeds == []

    def test_init_with_seeds(self, mock_pyradamsa):
        """RadamsaMutator can be created with initial seeds."""
        mock_module, mock_instance = mock_pyradamsa
        from src.oida.fuzz.core.mutation.radamsa import RadamsaMutator

        seeds = [b"seed1", b"seed2", b"seed3"]
        mutator = RadamsaMutator(seeds=seeds)
        assert len(mutator.seeds) == 3

    def test_init_raises_without_pyradamsa(self):
        """RadamsaMutator raises if pyradamsa not installed."""
        # Remove pyradamsa from modules if present
        original = sys.modules.get("pyradamsa")
        sys.modules["pyradamsa"] = None  # Force ImportError

        # Clear cached import
        if "src.oida.fuzz.core.mutation.radamsa" in sys.modules:
            del sys.modules["src.oida.fuzz.core.mutation.radamsa"]

        try:
            with pytest.raises(RuntimeError, match="pyradamsa not installed"):
                from src.oida.fuzz.core.mutation.radamsa import RadamsaMutator

                RadamsaMutator()
        finally:
            # Restore
            if original is not None:
                sys.modules["pyradamsa"] = original
            elif "pyradamsa" in sys.modules:
                del sys.modules["pyradamsa"]
            if "src.oida.fuzz.core.mutation.radamsa" in sys.modules:
                del sys.modules["src.oida.fuzz.core.mutation.radamsa"]


class TestRadamsaMutatorAddSeed:
    """Tests for adding seeds to mutator."""

    def test_add_seed(self, mock_pyradamsa):
        """Seeds can be added after creation."""
        mock_module, mock_instance = mock_pyradamsa
        from src.oida.fuzz.core.mutation.radamsa import RadamsaMutator

        mutator = RadamsaMutator()
        mutator.add_seed(b"new_seed")
        assert b"new_seed" in mutator.seeds

    def test_add_multiple_seeds(self, mock_pyradamsa):
        """Multiple seeds can be added."""
        mock_module, mock_instance = mock_pyradamsa
        from src.oida.fuzz.core.mutation.radamsa import RadamsaMutator

        mutator = RadamsaMutator()
        mutator.add_seed(b"seed1")
        mutator.add_seed(b"seed2")
        mutator.add_seed(b"seed3")
        assert len(mutator.seeds) == 3


# =============================================================================
# Test RadamsaMutator.mutate()
# =============================================================================


class TestRadamsaMutatorMutate:
    """Tests for single mutation generation."""

    def test_mutate_returns_bytes(self, mock_pyradamsa):
        """mutate() returns bytes."""
        mock_module, mock_instance = mock_pyradamsa
        mock_instance.fuzz.return_value = b"mutated_data"

        from src.oida.fuzz.core.mutation.radamsa import RadamsaMutator

        mutator = RadamsaMutator()
        result = mutator.mutate(b"test_data")
        assert isinstance(result, bytes)

    def test_mutate_calls_radamsa_fuzz(self, mock_pyradamsa):
        """mutate() calls pyradamsa.fuzz()."""
        mock_module, mock_instance = mock_pyradamsa
        mock_instance.fuzz.return_value = b"mutated"

        from src.oida.fuzz.core.mutation.radamsa import RadamsaMutator

        mutator = RadamsaMutator()
        mutator.mutate(b"input_data")
        mock_instance.fuzz.assert_called_once()

    def test_mutate_with_seed(self, mock_pyradamsa):
        """mutate() passes seed to pyradamsa."""
        mock_module, mock_instance = mock_pyradamsa
        mock_instance.fuzz.return_value = b"mutated"

        from src.oida.fuzz.core.mutation.radamsa import RadamsaMutator

        mutator = RadamsaMutator()
        mutator.mutate(b"input_data", seed=42)
        mock_instance.fuzz.assert_called_with(b"input_data", seed=42)

    def test_mutate_deterministic_with_same_seed(self, mock_pyradamsa):
        """Same seed produces same mutation."""
        mock_module, mock_instance = mock_pyradamsa

        def deterministic_fuzz(data, seed=None):
            return b"mutation_" + str(seed).encode()

        mock_instance.fuzz.side_effect = deterministic_fuzz

        from src.oida.fuzz.core.mutation.radamsa import RadamsaMutator

        mutator = RadamsaMutator()

        result1 = mutator.mutate(b"test", seed=123)
        result2 = mutator.mutate(b"test", seed=123)
        assert result1 == result2


# =============================================================================
# Test RadamsaMutator.mutate_batch()
# =============================================================================


class TestRadamsaMutatorMutateBatch:
    """Tests for batch mutation generation."""

    def test_mutate_batch_returns_list(self, mock_pyradamsa):
        """mutate_batch() returns a list."""
        mock_module, mock_instance = mock_pyradamsa
        mock_instance.fuzz.return_value = b"mutated"

        from src.oida.fuzz.core.mutation.radamsa import RadamsaMutator

        mutator = RadamsaMutator()
        result = mutator.mutate_batch(b"test", count=5)
        assert isinstance(result, list)
        assert len(result) == 5

    def test_mutate_batch_correct_count(self, mock_pyradamsa):
        """mutate_batch() generates correct number of mutations."""
        mock_module, mock_instance = mock_pyradamsa
        mock_instance.fuzz.return_value = b"mutated"

        from src.oida.fuzz.core.mutation.radamsa import RadamsaMutator

        mutator = RadamsaMutator()
        result = mutator.mutate_batch(b"test", count=100)
        assert len(result) == 100

    def test_mutate_batch_uses_incremental_seeds(self, mock_pyradamsa):
        """mutate_batch() uses incremental seeds starting from start_seed."""
        mock_module, mock_instance = mock_pyradamsa
        seeds_used = []

        def track_seeds(data, seed=None):
            seeds_used.append(seed)
            return b"mutated"

        mock_instance.fuzz.side_effect = track_seeds

        from src.oida.fuzz.core.mutation.radamsa import RadamsaMutator

        mutator = RadamsaMutator()
        mutator.mutate_batch(b"test", count=5, start_seed=10)
        assert seeds_used == [10, 11, 12, 13, 14]


# =============================================================================
# Test RadamsaMutator.mutation_stream()
# =============================================================================


class TestRadamsaMutatorMutationStream:
    """Tests for streaming mutation generation."""

    def test_mutation_stream_yields(self, mock_pyradamsa):
        """mutation_stream() yields mutations."""
        mock_module, mock_instance = mock_pyradamsa
        mock_instance.fuzz.return_value = b"mutated"

        from src.oida.fuzz.core.mutation.radamsa import RadamsaMutator

        mutator = RadamsaMutator(seeds=[b"seed1"])
        stream = mutator.mutation_stream(count=5)
        results = list(stream)
        assert len(results) == 5

    def test_mutation_stream_cycles_seeds(self, mock_pyradamsa):
        """mutation_stream() cycles through seeds."""
        mock_module, mock_instance = mock_pyradamsa
        data_used = []

        def track_data(data, seed=None):
            data_used.append(data)
            return b"mutated"

        mock_instance.fuzz.side_effect = track_data

        from src.oida.fuzz.core.mutation.radamsa import RadamsaMutator

        mutator = RadamsaMutator(seeds=[b"A", b"B", b"C"])
        list(mutator.mutation_stream(count=6))
        # Should cycle: A, B, C, A, B, C
        assert data_used == [b"A", b"B", b"C", b"A", b"B", b"C"]

    def test_mutation_stream_raises_without_seeds(self, mock_pyradamsa):
        """mutation_stream() raises if no seeds loaded."""
        mock_module, mock_instance = mock_pyradamsa

        from src.oida.fuzz.core.mutation.radamsa import RadamsaMutator

        mutator = RadamsaMutator()
        with pytest.raises(ValueError, match="No seeds loaded"):
            list(mutator.mutation_stream(count=5))


# =============================================================================
# Test RadamsaMutator.save_mutations_to_files()
# =============================================================================


class TestRadamsaMutatorSaveToFiles:
    """Tests for saving mutations to files."""

    def test_save_creates_files(self, mock_pyradamsa):
        """save_mutations_to_files() creates mutation files."""
        mock_module, mock_instance = mock_pyradamsa
        mock_instance.fuzz.return_value = b"mutated_content"

        from src.oida.fuzz.core.mutation.radamsa import RadamsaMutator

        with tempfile.TemporaryDirectory() as tmpdir:
            mutator = RadamsaMutator(seeds=[b"seed"])
            files = mutator.save_mutations_to_files(tmpdir, count=3)
            assert len(files) == 3
            for f in files:
                assert os.path.exists(f)

    def test_save_file_content(self, mock_pyradamsa):
        """Saved files contain mutation content."""
        mock_module, mock_instance = mock_pyradamsa
        mock_instance.fuzz.return_value = b"expected_content"

        from src.oida.fuzz.core.mutation.radamsa import RadamsaMutator

        with tempfile.TemporaryDirectory() as tmpdir:
            mutator = RadamsaMutator(seeds=[b"seed"])
            files = mutator.save_mutations_to_files(tmpdir, count=1)

            with open(files[0], "rb") as f:
                content = f.read()
            assert content == b"expected_content"

    def test_save_raises_without_seeds(self, mock_pyradamsa):
        """save_mutations_to_files() raises if no seeds."""
        mock_module, mock_instance = mock_pyradamsa

        from src.oida.fuzz.core.mutation.radamsa import RadamsaMutator

        with tempfile.TemporaryDirectory() as tmpdir:
            mutator = RadamsaMutator()
            with pytest.raises(ValueError, match="No seeds loaded"):
                mutator.save_mutations_to_files(tmpdir, count=5)

    def test_save_creates_directory(self, mock_pyradamsa):
        """save_mutations_to_files() creates output directory if needed."""
        mock_module, mock_instance = mock_pyradamsa
        mock_instance.fuzz.return_value = b"content"

        from src.oida.fuzz.core.mutation.radamsa import RadamsaMutator

        with tempfile.TemporaryDirectory() as tmpdir:
            new_dir = os.path.join(tmpdir, "new_subdir")
            mutator = RadamsaMutator(seeds=[b"seed"])
            mutator.save_mutations_to_files(new_dir, count=1)
            assert os.path.isdir(new_dir)


# =============================================================================
# Test SeedLoader
# =============================================================================


class TestSeedLoaderFromDirectory:
    """Tests for SeedLoader.from_directory()."""

    def test_load_from_directory(self):
        """Seeds are loaded from directory."""
        from src.oida.fuzz.core.mutation.radamsa import SeedLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create seed files
            for i in range(3):
                with open(os.path.join(tmpdir, f"seed_{i}.bin"), "wb") as f:
                    f.write(f"seed_content_{i}".encode())

            seeds = SeedLoader.from_directory(tmpdir)
            assert len(seeds) == 3

    def test_load_from_directory_skips_empty(self):
        """Empty files are skipped."""
        from src.oida.fuzz.core.mutation.radamsa import SeedLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create one non-empty and one empty file
            with open(os.path.join(tmpdir, "nonempty.bin"), "wb") as f:
                f.write(b"content")
            with open(os.path.join(tmpdir, "empty.bin"), "wb") as f:
                pass  # Empty file

            seeds = SeedLoader.from_directory(tmpdir)
            assert len(seeds) == 1

    def test_load_from_directory_raises_not_found(self):
        """FileNotFoundError raised for missing directory."""
        from src.oida.fuzz.core.mutation.radamsa import SeedLoader

        with pytest.raises(FileNotFoundError):
            SeedLoader.from_directory("/nonexistent/path")

    def test_load_from_directory_raises_not_dir(self):
        """NotADirectoryError raised for file path."""
        from src.oida.fuzz.core.mutation.radamsa import SeedLoader

        with tempfile.NamedTemporaryFile() as tmpfile:
            with pytest.raises(NotADirectoryError):
                SeedLoader.from_directory(tmpfile.name)


class TestSeedLoaderFromFiles:
    """Tests for SeedLoader.from_files()."""

    def test_load_from_file_patterns(self):
        """Seeds are loaded from file patterns."""
        from src.oida.fuzz.core.mutation.radamsa import SeedLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create seed files
            for i in range(3):
                with open(os.path.join(tmpdir, f"seed_{i}.bin"), "wb") as f:
                    f.write(f"content_{i}".encode())

            pattern = os.path.join(tmpdir, "*.bin")
            seeds = SeedLoader.from_files([pattern])
            assert len(seeds) == 3

    def test_load_from_multiple_patterns(self):
        """Seeds are loaded from multiple patterns."""
        from src.oida.fuzz.core.mutation.radamsa import SeedLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create .bin and .txt files
            with open(os.path.join(tmpdir, "seed.bin"), "wb") as f:
                f.write(b"bin_content")
            with open(os.path.join(tmpdir, "seed.txt"), "wb") as f:
                f.write(b"txt_content")

            patterns = [
                os.path.join(tmpdir, "*.bin"),
                os.path.join(tmpdir, "*.txt"),
            ]
            seeds = SeedLoader.from_files(patterns)
            assert len(seeds) == 2

    def test_load_from_files_handles_no_match(self):
        """No error for patterns with no matches."""
        from src.oida.fuzz.core.mutation.radamsa import SeedLoader

        seeds = SeedLoader.from_files(["/nonexistent/*.xyz"])
        assert seeds == []


class TestSeedLoaderFromStrings:
    """Tests for SeedLoader.from_strings()."""

    def test_convert_strings_to_bytes(self):
        """Strings are converted to bytes."""
        from src.oida.fuzz.core.mutation.radamsa import SeedLoader

        strings = ["hello", "world", "test"]
        seeds = SeedLoader.from_strings(strings)
        assert seeds == [b"hello", b"world", b"test"]

    def test_preserve_bytes(self):
        """Bytes are preserved unchanged."""
        from src.oida.fuzz.core.mutation.radamsa import SeedLoader

        mixed = ["string", b"bytes"]
        seeds = SeedLoader.from_strings(mixed)
        assert seeds == [b"string", b"bytes"]


# =============================================================================
# Test Edge Cases and Error Handling
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases."""

    def test_empty_data_mutation(self, mock_pyradamsa):
        """Empty data can be mutated."""
        mock_module, mock_instance = mock_pyradamsa
        mock_instance.fuzz.return_value = b"something"

        from src.oida.fuzz.core.mutation.radamsa import RadamsaMutator

        mutator = RadamsaMutator()
        result = mutator.mutate(b"")
        assert result == b"something"

    def test_large_mutation_count(self, mock_pyradamsa):
        """Large mutation counts work correctly."""
        mock_module, mock_instance = mock_pyradamsa
        mock_instance.fuzz.return_value = b"m"

        from src.oida.fuzz.core.mutation.radamsa import RadamsaMutator

        mutator = RadamsaMutator()
        result = mutator.mutate_batch(b"test", count=10000)
        assert len(result) == 10000

    def test_binary_data_with_all_bytes(self, mock_pyradamsa):
        """All byte values (0x00-0xFF) can be in data."""
        mock_module, mock_instance = mock_pyradamsa
        mock_instance.fuzz.return_value = bytes(range(256))

        from src.oida.fuzz.core.mutation.radamsa import RadamsaMutator

        mutator = RadamsaMutator()
        result = mutator.mutate(bytes(range(256)))
        assert len(result) == 256


# =============================================================================
# Test Integration with Protocol Fuzzing
# =============================================================================


class TestProtocolIntegration:
    """Tests for protocol fuzzing integration."""

    def test_http_seed_mutation(self, mock_pyradamsa):
        """HTTP request seeds can be mutated."""
        mock_module, mock_instance = mock_pyradamsa
        mock_instance.fuzz.return_value = b"GET /fuzzed HTTP/1.1\r\n\r\n"

        from src.oida.fuzz.core.mutation.radamsa import RadamsaMutator

        http_seeds = [
            b"GET / HTTP/1.1\r\nHost: test\r\n\r\n",
            b"POST /api HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
        ]
        mutator = RadamsaMutator(seeds=http_seeds)
        mutations = list(mutator.mutation_stream(count=10))
        assert len(mutations) == 10

    def test_modbus_seed_mutation(self, mock_pyradamsa):
        """Modbus ADU seeds can be mutated."""
        mock_module, mock_instance = mock_pyradamsa
        mock_instance.fuzz.return_value = b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x0a"

        from src.oida.fuzz.core.mutation.radamsa import RadamsaMutator

        modbus_seeds = [
            b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x0a",  # Read holding registers
            b"\x00\x02\x00\x00\x00\x06\x01\x01\x00\x00\x00\x08",  # Read coils
        ]
        mutator = RadamsaMutator(seeds=modbus_seeds)
        result = mutator.mutate_batch(modbus_seeds[0], count=100)
        assert len(result) == 100


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
