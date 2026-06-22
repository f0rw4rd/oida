"""Shared helpers for the IEC 60870-5 passive listeners (iec101 / iec103 / iec104).

These three protocols share the same ASDU framing concepts. This module
centralizes the two pieces of logic that previously diverged per-file:

1. ``parse_asdu_field()`` — ASDU type-ID / COT integer parse. tshark renders
   these ``FT_UINT8`` fields in DECIMAL (a real ``0x`` prefix is still honored).
   Single-sourcing the base here prevents per-listener drift — iec103 once
   parsed these with ``base=16``, turning decimal ``"20"`` into ``32`` and
   mislabeling every multi-digit command/COT.

2. ``classify_rw()`` — the read/write/control/file/error classification ladder
   for IEC-101/104, which was previously copy-pasted identically in iec101 and
   twice in iec104.

iec103 (the protection profile) keeps its own direction-split type/COT maps and
its own rw rules — those are genuinely different semantics — but it shares
``parse_asdu_field()`` so the parse base can no longer diverge.
"""

from __future__ import annotations

from typing import Any, Set

from .pyshark_base import PySharkListenerBase


def parse_asdu_field(raw: Any, default: Any = 0) -> Any:
    """Parse an IEC 60870-5 ASDU type-ID or COT field as a base-10 integer.

    Delegates to ``PySharkListenerBase._parse_int`` (base 10, ``0x``-prefix
    aware) so every IEC listener resolves these decimal tshark fields the same
    way. Returns *default* for ``None`` or unparseable input.
    """
    return PySharkListenerBase._parse_int(raw, default)


def classify_rw(
    type_id: int,
    is_error_cot: bool,
    *,
    write_ids: Set[int],
    read_ids: Set[int],
    system_ids: Set[int],
    file_ids: Set[int],
) -> str:
    """Classify an IEC-101/104 ASDU's access intent.

    Mirrors the historical ladder exactly: error > write > read(command) >
    control(system) > file, with a ``type_id <= 44`` monitor/read fallback and
    a write default for everything above.
    """
    if is_error_cot:
        return "error"
    if type_id in write_ids:
        return "write"
    if type_id in read_ids:
        return "read"
    if type_id in system_ids:
        return "control"
    if type_id in file_ids:
        return "file"
    if type_id <= 44:
        return "read"
    return "write"
