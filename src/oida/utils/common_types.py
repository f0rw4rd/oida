#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Shared utility functions for ICS protocol scanners (boolean parsing and
directory-traversal-safe path handling).
"""

import os
from typing import Optional


def parse_bool(value):
    """Parse a value into a boolean.

    Accepts bool, string ('true'/'yes'/'y'/'1' -> True), else False.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.lower() in ("true", "yes", "y", "1"):
        return True
    return False


def safe_file_path(path_str: str, base_dir: Optional[str] = None) -> str:
    """Validate and resolve a file path, blocking directory traversal.

    Resolves the path to an absolute path and ensures it does not escape
    the expected base directory.  When *base_dir* is ``None`` the current
    working directory is used as the boundary.

    Args:
        path_str: The file path to validate (may be user-supplied).
        base_dir: Optional base directory the path must stay within.
                  Defaults to ``os.getcwd()``.

    Returns:
        The resolved absolute path as a string.

    Raises:
        ValueError: If the resolved path escapes *base_dir*.
    """
    if base_dir is None:
        base_dir = os.getcwd()

    resolved = os.path.realpath(path_str)
    base = os.path.realpath(base_dir)

    # Ensure the resolved path is within (or equal to) the base directory.
    # Append os.sep to avoid prefix false-positives (e.g. /tmp/evil vs /tmp/ev).
    if not (resolved == base or resolved.startswith(base + os.sep)):
        raise ValueError(f"Path traversal blocked: '{path_str}' resolves outside allowed directory")

    return resolved


def safe_output_path(filename: str, output_dir: str) -> str:
    """Build a safe output file path inside *output_dir*.

    Strips directory components from *filename* (using ``os.path.basename``)
    and validates the resulting path stays within *output_dir*.

    Args:
        filename:   Potentially untrusted filename (may contain ``../``).
        output_dir: Directory where the file should be written.

    Returns:
        Resolved absolute path inside *output_dir*.

    Raises:
        ValueError: If the sanitised path still escapes *output_dir*.
    """
    basename = os.path.basename(filename.replace("\\", "/"))
    if not basename:
        raise ValueError(f"Invalid filename: '{filename}'")
    candidate = os.path.join(output_dir, basename)
    return safe_file_path(candidate, base_dir=output_dir)
