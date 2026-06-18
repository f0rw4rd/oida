"""
Radamsa-based mutation engine for OIDA fuzzer

Provides mutation capabilities using the pyradamsa library for:
1. Raw seed-based fuzzing
2. Field-level mutations (alternative to boofuzz's built-in libraries)
"""

from pathlib import Path
from typing import List, Iterator, Optional
import glob

from ....utils.ics_logger import get_logger

_log = get_logger("RADAMSA", "mutator", 0)


class RadamsaMutator:
    """
    Mutation engine using pyradamsa

    Generates mutations from seed data using Radamsa's mutation algorithms.
    Supports both batch generation and streaming mutations.
    """

    def __init__(self, seeds: Optional[List[bytes]] = None):
        """
        Initialize Radamsa mutator

        Args:
            seeds: List of seed data to mutate (optional)
        """
        self.seeds = seeds or []
        self._radamsa = None
        self._init_radamsa()

    def _init_radamsa(self):
        """Initialize pyradamsa library"""
        try:
            import pyradamsa

            self._radamsa = pyradamsa.Radamsa()
            _log.display("Radamsa mutator initialized successfully")
        except ImportError:
            raise RuntimeError(
                "pyradamsa not installed!\n"
                "Install with: pip install pyradamsa\n"
                "Or add to requirements: pip install -e .[radamsa]"
            )

    def add_seed(self, seed: bytes):
        """Add a seed to the mutation pool"""
        self.seeds.append(seed)

    def mutate(self, data: bytes, seed: Optional[int] = None) -> bytes:
        """
        Generate a single mutation

        Args:
            data: Data to mutate
            seed: Random seed for reproducibility (optional)

        Returns:
            Mutated data
        """
        if self._radamsa is None:
            self._init_radamsa()

        return self._radamsa.fuzz(data, seed=seed)

    def mutate_batch(self, data: bytes, count: int, start_seed: int = 0) -> List[bytes]:
        """
        Generate multiple mutations of the same data

        Args:
            data: Data to mutate
            count: Number of mutations to generate
            start_seed: Starting seed value

        Returns:
            List of mutated data
        """
        mutations = []
        for i in range(count):
            mutated = self.mutate(data, seed=start_seed + i)
            mutations.append(mutated)
        return mutations

    def mutation_stream(self, count: int = 100) -> Iterator[bytes]:
        """
        Generate mutations from seed pool as a stream

        Args:
            count: Number of mutations to generate

        Yields:
            Mutated data
        """
        if not self.seeds:
            raise ValueError("No seeds loaded. Add seeds with add_seed() first.")

        for i in range(count):
            seed_idx = i % len(self.seeds)
            seed_data = self.seeds[seed_idx]
            yield self.mutate(seed_data, seed=i)

    def save_mutations_to_files(self, output_dir: str, count: int) -> List[str]:
        """
        Generate mutations and save to files (for use with boofuzz FromFile)

        Args:
            output_dir: Directory to save mutation files
            count: Number of mutations to generate

        Returns:
            List of file paths
        """
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        if not self.seeds:
            raise ValueError("No seeds loaded")

        generated_files = []
        for i, mutated in enumerate(self.mutation_stream(count)):
            filepath = Path(output_dir) / f"mutation_{i:05d}.bin"
            with open(filepath, "wb") as f:
                f.write(mutated)
            generated_files.append(str(filepath))

            if (i + 1) % 100 == 0:
                _log.display(f"Generated {i + 1}/{count} mutations...")

        _log.display(f"Saved {len(generated_files)} mutations to {output_dir}")
        return generated_files


class SeedLoader:
    """Utility to load seeds from various sources"""

    @staticmethod
    def from_directory(directory: str) -> List[bytes]:
        """
        Load all files from a directory as seeds

        Args:
            directory: Directory path

        Returns:
            List of seed data
        """
        seeds = []
        dir_path = Path(directory)

        if not dir_path.exists():
            raise FileNotFoundError(f"Seed directory not found: {directory}")

        if not dir_path.is_dir():
            raise NotADirectoryError(f"Not a directory: {directory}")

        for file_path in sorted(dir_path.glob("*")):
            if file_path.is_file():
                try:
                    with open(file_path, "rb") as f:
                        data = f.read()
                        if len(data) > 0:
                            seeds.append(data)
                            _log.debug(f"Loaded seed: {file_path.name} ({len(data)} bytes)")
                except Exception as e:
                    _log.warning(f"Failed to load {file_path}: {e}")

        _log.display(f"Loaded {len(seeds)} seeds from {directory}")
        return seeds

    @staticmethod
    def from_files(file_patterns: List[str]) -> List[bytes]:
        """
        Load seeds from file patterns (supports glob)

        Args:
            file_patterns: List of file paths or glob patterns

        Returns:
            List of seed data
        """
        seeds = []

        for pattern in file_patterns:
            matches = glob.glob(pattern)
            if not matches:
                _log.warning(f"No files match pattern: {pattern}")
                continue

            for filepath in matches:
                try:
                    with open(filepath, "rb") as f:
                        data = f.read()
                        if len(data) > 0:
                            seeds.append(data)
                            _log.debug(f"Loaded seed: {filepath} ({len(data)} bytes)")
                except Exception as e:
                    _log.warning(f"Failed to load {filepath}: {e}")

        _log.display(f"Loaded {len(seeds)} seeds from {len(file_patterns)} pattern(s)")
        return seeds

    @staticmethod
    def from_strings(strings: List[str]) -> List[bytes]:
        """
        Convert string list to bytes seeds

        Args:
            strings: List of string seeds

        Returns:
            List of byte seeds
        """
        return [s.encode() if isinstance(s, str) else s for s in strings]
