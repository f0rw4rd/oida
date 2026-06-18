"""BCU key brute-force utilities.

Provides functions for BCU (Bus Coupling Unit) authentication key handling,
including validation, file loading, and range generation.
"""

from typing import List

from ...utils import ics_logger as module
from .helpers import validate_bcu_key
from .constants import MAX_KEY_RANGE


def load_keys_from_file(filepath: str) -> List[str]:
    """Load and validate BCU keys from file.

    Args:
        filepath: Path to key file (one hex key per line)

    Returns:
        List of validated uppercase hex keys

    Raises:
        ValueError: If any key is invalid (with line number)
        FileNotFoundError: If file doesn't exist
    """
    keys = []
    with open(filepath, "r") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            # Skip empty lines and comments
            if not line or line.startswith("#"):
                continue
            # Validate hex format
            if not validate_bcu_key(line):
                raise ValueError(
                    f"Invalid key at line {line_num}: '{line}' "
                    f"(must be exactly 8 hex characters 0-9A-F)"
                )
            keys.append(line.upper())
    return keys


def parse_key_range(range_str: str) -> List[str]:
    """Parse hex key range like '00000000-000000FF'.

    Args:
        range_str: Range string in format 'START-END'

    Returns:
        List of hex keys in the range (inclusive)

    Raises:
        ValueError: If range format is invalid
    """
    parts = range_str.split("-")
    if len(parts) != 2:
        raise ValueError(f"Invalid range format: '{range_str}' (use START-END)")

    start_str, end_str = parts[0].strip(), parts[1].strip()

    if not validate_bcu_key(start_str):
        raise ValueError(f"Invalid start key: '{start_str}' (must be 8 hex characters)")
    if not validate_bcu_key(end_str):
        raise ValueError(f"Invalid end key: '{end_str}' (must be 8 hex characters)")

    start = int(start_str, 16)
    end = int(end_str, 16)

    if start > end:
        raise ValueError(f"Start key greater than end: {start_str} > {end_str}")

    range_size = end - start + 1

    if range_size > MAX_KEY_RANGE:
        raise ValueError(
            f"Key range too large: {range_size} keys (max {MAX_KEY_RANGE}). Use smaller ranges."
        )

    if range_size > 10000:
        module.warn(f"Large key range: {range_size} keys (this may take a while)")

    # Generate keys in range
    return [f"{i:08X}" for i in range(start, end + 1)]
