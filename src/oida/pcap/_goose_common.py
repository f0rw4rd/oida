"""Shared helpers for the GOOSE passive listeners (goose / rgoose).

L2 GOOSE and R-GOOSE (GOOSE-over-TLS/TCP, IEC 61850-90-5) carry the identical
GOOSE PDU and are decoded by the same tshark dissector fields. This module
centralizes the two pieces of field-extraction logic that previously diverged
per-file only in naming:

1. ``collect_field_values()`` - pulls every instance of a PyShark field into a
   values list, handling both EK mode (fields are Python lists) and XML mode
   (fields expose an ``.all_fields`` iterator).
2. ``format_bool_display()`` - renders a GOOSE boolean field as ``"T"``/``"F"``.
"""

from __future__ import annotations

from typing import Callable, List, Optional


def collect_field_values(
    layer,
    field_name: str,
    values: List[str],
    formatter: Optional[Callable[[str], str]] = None,
) -> None:
    """Collect all instances of a field from a PyShark layer into ``values``.

    Handles both EK mode (fields are Python lists) and XML mode (fields have
    ``.all_fields`` iterators).
    """
    raw_attr = getattr(layer, field_name, None)
    if raw_attr is None:
        return

    # EK mode: multi-value fields are Python lists
    if isinstance(raw_attr, list):
        for item in raw_attr:
            val = str(item)
            if formatter:
                val = formatter(val)
            values.append(val)
        return

    # XML mode: try .all_fields iterator
    try:
        for fld in raw_attr.all_fields:
            val = str(fld.show)
            if formatter:
                val = formatter(val)
            values.append(val)
    except Exception:
        val = str(raw_attr)
        if formatter:
            val = formatter(val)
        values.append(val)


def format_bool_display(val: str) -> str:
    """Format a boolean value for display."""
    if val in ("True", "1"):
        return "T"
    if val in ("False", "0"):
        return "F"
    return val
