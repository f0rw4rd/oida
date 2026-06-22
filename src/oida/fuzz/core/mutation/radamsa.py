"""
Seed loading utilities for the OIDA fuzzer.

Provides the SeedLoader helper for loading raw seed corpora from
directories, glob patterns, or in-memory strings.
"""

from pathlib import Path
from typing import List
import glob

from ....utils.ics_logger import get_logger

_log = get_logger("RADAMSA", "mutator", 0)


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
