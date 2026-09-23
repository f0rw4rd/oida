"""Shared harvest/credential-summary helpers for the MongoDB and Redis
passive listeners.

Both listeners track the same three pieces of per-connection state
(``self.credentials``, ``self._write_ops``, ``self._alerts``) and previously
duplicated identical aggregation logic for exposing them: a credentials
summary passthrough, a client/server write-op tally, and an ``_alerts``
merge into ``harvest()``. This module single-sources that aggregation via a
mixin so the two wire protocols (which remain otherwise unrelated) can't
drift on it.
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple


class WriteOpsHarvestMixin:
    """Mixin providing credential/write-op summaries and harvest merging.

    Expects the including class to maintain ``self.credentials``,
    ``self._write_ops``, and ``self._alerts`` (all set up in each listener's
    ``__init__``), and to sit before ``PySharkListenerBase`` in the MRO so
    ``super().harvest()`` reaches the base implementation.
    """

    def get_credentials_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all extracted credentials."""
        return list(self.credentials)

    def get_write_operations(self) -> List[Dict[str, Any]]:
        """Get aggregated write operations."""
        if not self._write_ops:
            return []
        pairs: Dict[Tuple[str, str], Dict[str, Any]] = {}
        for op in self._write_ops:
            key = (op["client"], op["server"])
            if key not in pairs:
                pairs[key] = {"client": op["client"], "server": op["server"], "write_count": 0}
            pairs[key]["write_count"] += 1
        return list(pairs.values())

    def harvest(self) -> Dict[str, Any]:
        """Return structured harvest data."""
        result = super().harvest()
        if self._alerts:
            if not result:
                result = {"tables": [], "alerts": []}
            alerts = result.get("alerts", [])
            for alert in self._alerts:
                if alert not in alerts:
                    alerts.append(alert)
            result["alerts"] = alerts
        return result
