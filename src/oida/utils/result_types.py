"""Typed shape of the per-target scan-result envelope.

Every dispatched scan (Layer-2 ``connection`` subclass) produces a single
result dict describing *one* target. Historically that dict was an untyped
``Dict[str, Any]`` - exporters and CLI callers indexed an ``Any``, so a typo in
an envelope key (``"sucess"``) or a wrong-typed field was invisible until
runtime.

``ScanResult`` names that envelope so consumers get a documented, checkable
shape at the boundary (``connection.get_results()`` / ``cli.scan_target()``).

Design notes
------------
* ``total=False`` - not every field is present at every moment. ``success`` is
  ``None`` until ``proto_flow()`` resolves it; ``error`` only appears on failure.
* The envelope is *typed*, but the per-protocol payload is not: protocols write
  their findings into ``data`` (free-form ``Dict[str, Any]``). A handful of
  protocols also attach extra top-level keys (``tls``, ``tables``, ``devices``,
  ``statistics``, ...). Those remain legal because the *underlying* container is
  still a mutable ``Dict[str, Any]`` - ``ScanResult`` is the documented view
  applied at the boundary via ``cast``, not a straitjacket on internal writes.
  New code should prefer nesting protocol-specific output under ``data``.
"""

from __future__ import annotations

from typing import Any, Dict, Optional, TypedDict


class ScanResult(TypedDict, total=False):
    """The outer envelope returned for a single scanned target."""

    host: str
    ip: str
    protocol: str
    port: Optional[int]
    success: Optional[bool]
    error: str
    data: Dict[str, Any]
