"""
Shared payload resolution utilities.

Provides a common ``@file`` loading pattern used across protocols
(Modbus, CoAP, DNP3, etc.) to load binary payloads from local files.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional, Tuple


def resolve_file_payload(value: str) -> Tuple[bytes, Optional[str]]:
    """Resolve a string that may reference a local file via ``@path``.

    If *value* starts with ``@``, the remainder is treated as a file path
    and its binary contents are returned.  Otherwise *value* is returned
    unchanged (the caller decides how to interpret the raw string).

    Returns:
        A ``(data, file_path)`` tuple.

        * When a file was read: ``data`` contains the file bytes and
          ``file_path`` is the resolved path string.
        * When no ``@`` prefix is present: ``data`` is *None* and
          ``file_path`` is *None*.  The caller should fall back to its
          own parsing (hex decoding, UTF-8 encoding, etc.).

    Raises:
        FileNotFoundError: If the ``@``-referenced path does not exist.
        OSError: If the file exists but cannot be read.
    """
    if not value or not value.startswith("@"):
        return None, None

    file_path = value[1:]
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Payload file not found: {file_path}")

    return path.read_bytes(), file_path
