"""
TASE.2 Transfer Sets Mixin

Handles Block 2 (RBE) transfer set operations:
- Transfer set discovery
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List

if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


class TransferSetsMixin(_ScannerBase):
    """Mixin providing TASE.2 transfer set (Block 2 - RBE) operations."""

    def _discover_transfer_sets(self, connection: Any) -> List[Dict[str, Any]]:
        """Discover DS transfer sets (Block 2 - RBE)."""
        transfer_sets = []

        for domain in self.domains:
            try:
                ts_list = connection.get_transfer_sets(domain.name)

                for ts in ts_list:
                    ts_info = {
                        "domain": domain.name,
                        "name": ts.name,
                        "data_set": ts.data_set,
                        "interval": ts.interval,
                        "rbe_enabled": ts.rbe_enabled,
                        "buffer_time": ts.buffer_time,
                        "integrity_time": ts.integrity_time,
                    }
                    transfer_sets.append(ts_info)

                    self.logger.display(
                        f"  Transfer Set: {domain.name}/{ts.name} (RBE: {ts.rbe_enabled})"
                    )

            except Exception as e:
                self.logger.debug(f"Error getting transfer sets for {domain.name}: {e}")

        if transfer_sets:
            self.logger.display(f"Found {len(transfer_sets)} transfer set(s)")

        return transfer_sets
