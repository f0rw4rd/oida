"""
Tests for the seed loading utilities.

Tests cover:
- SeedLoader: Seed loading utilities (directory, glob patterns, strings)
"""

import pytest
import tempfile
import os


# =============================================================================
# Test SeedLoader
# =============================================================================


class TestSeedLoaderFromDirectory:
    """Tests for SeedLoader.from_directory()."""

    def test_load_from_directory(self):
        """Seeds are loaded from directory."""
        from oida.fuzz.core.mutation.radamsa import SeedLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create seed files
            for i in range(3):
                with open(os.path.join(tmpdir, f"seed_{i}.bin"), "wb") as f:
                    f.write(f"seed_content_{i}".encode())

            seeds = SeedLoader.from_directory(tmpdir)
            assert len(seeds) == 3

    def test_load_from_directory_skips_empty(self):
        """Empty files are skipped."""
        from oida.fuzz.core.mutation.radamsa import SeedLoader

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
        from oida.fuzz.core.mutation.radamsa import SeedLoader

        with pytest.raises(FileNotFoundError):
            SeedLoader.from_directory("/nonexistent/path")

    def test_load_from_directory_raises_not_dir(self):
        """NotADirectoryError raised for file path."""
        from oida.fuzz.core.mutation.radamsa import SeedLoader

        with tempfile.NamedTemporaryFile() as tmpfile:
            with pytest.raises(NotADirectoryError):
                SeedLoader.from_directory(tmpfile.name)


class TestSeedLoaderFromFiles:
    """Tests for SeedLoader.from_files()."""

    def test_load_from_file_patterns(self):
        """Seeds are loaded from file patterns."""
        from oida.fuzz.core.mutation.radamsa import SeedLoader

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
        from oida.fuzz.core.mutation.radamsa import SeedLoader

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
        from oida.fuzz.core.mutation.radamsa import SeedLoader

        seeds = SeedLoader.from_files(["/nonexistent/*.xyz"])
        assert seeds == []


class TestSeedLoaderFromStrings:
    """Tests for SeedLoader.from_strings()."""

    def test_convert_strings_to_bytes(self):
        """Strings are converted to bytes."""
        from oida.fuzz.core.mutation.radamsa import SeedLoader

        strings = ["hello", "world", "test"]
        seeds = SeedLoader.from_strings(strings)
        assert seeds == [b"hello", b"world", b"test"]

    def test_preserve_bytes(self):
        """Bytes are preserved unchanged."""
        from oida.fuzz.core.mutation.radamsa import SeedLoader

        mixed = ["string", b"bytes"]
        seeds = SeedLoader.from_strings(mixed)
        assert seeds == [b"string", b"bytes"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
