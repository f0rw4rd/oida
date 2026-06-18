"""
TASE.2 Transfer Sets Mixin

Handles Block 2 (RBE) transfer set operations:
- Transfer set discovery
- Next available transfer set allocation
- DSConditions detection
- Transfer report acknowledgment (ACK/NACK)
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List, Optional

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

    # =========================================================================
    # Transfer Set Operations (Block 2 - RBE)
    # =========================================================================

    def get_next_ds_transfer_set(self, connection: Any, domain: str) -> Optional[str]:
        """
        Get the next available DSTransferSet name.

        Reads Next_DSTransfer_Set variable for dynamic allocation of transfer sets.

        Args:
            connection: Active TASE.2 connection
            domain: Domain name

        Returns:
            Name of next available transfer set, or None
        """
        try:
            next_ts = connection.read_point(domain, "Next_DSTransfer_Set")
            if next_ts and next_ts.value is not None:
                ts_name = str(next_ts.value)
                self.logger.display(f"Next available DSTransferSet: {domain}/{ts_name}")
                return ts_name
        except Exception as e:
            self.logger.debug(f"Could not read Next_DSTransfer_Set: {e}")

        return None

    def get_ds_conditions_detected(self, connection: Any, domain: str) -> Dict[str, bool]:
        """
        Get the DSConditions_Detected object.

        Indicates which conditions caused the last transfer report.

        Args:
            connection: Active TASE.2 connection
            domain: Domain name

        Returns:
            Dictionary with condition flags
        """
        conditions = {
            "interval_timeout": False,
            "object_change": False,
            "operator_request": False,
            "integrity_timeout": False,
            "other_external_event": False,
        }

        try:
            cond = connection.read_point(domain, "DSConditions_Detected")

            if cond and cond.value is not None:
                val = cond.value
                if isinstance(val, dict):
                    conditions["interval_timeout"] = val.get("IntervalTimeOut", False)
                    conditions["object_change"] = val.get("ObjectChange", False)
                    conditions["operator_request"] = val.get("OperatorRequest", False)
                    conditions["integrity_timeout"] = val.get("IntegrityTimeOut", False)
                    conditions["other_external_event"] = val.get("OtherExternalEvent", False)
                elif isinstance(val, (bytes, bytearray, int)):
                    # Parse bitstring
                    bits = (
                        int.from_bytes(val, "big") if isinstance(val, (bytes, bytearray)) else val
                    )
                    conditions["interval_timeout"] = bool(bits & 0x01)
                    conditions["object_change"] = bool(bits & 0x02)
                    conditions["operator_request"] = bool(bits & 0x04)
                    conditions["integrity_timeout"] = bool(bits & 0x08)
                    conditions["other_external_event"] = bool(bits & 0x10)

        except Exception as e:
            self.logger.debug(f"Could not read DSConditions_Detected: {e}")

        return conditions

    def send_transfer_report_ack(
        self, connection: Any, domain: str, transfer_set_name: str
    ) -> bool:
        """
        Send Transfer_Report_ACK to acknowledge a critical transfer report.

        Args:
            connection: Active TASE.2 connection
            domain: Domain name
            transfer_set_name: Name of the transfer set being acknowledged

        Returns:
            True if successful
        """
        try:
            connection.write_point(domain, "Transfer_Report_ACK", transfer_set_name)
            self.logger.display(f"Sent Transfer_Report_ACK for {domain}/{transfer_set_name}")
            return True
        except Exception as e:
            self.logger.debug(f"Failed to send Transfer_Report_ACK: {e}")
            return False

    def send_transfer_report_nack(
        self, connection: Any, domain: str, transfer_set_name: str
    ) -> bool:
        """
        Send Transfer_Report_NACK for a critical transfer report.

        Args:
            connection: Active TASE.2 connection
            domain: Domain name
            transfer_set_name: Name of the transfer set being rejected

        Returns:
            True if successful
        """
        try:
            connection.write_point(domain, "Transfer_Report_NACK", transfer_set_name)
            self.logger.display(f"Sent Transfer_Report_NACK for {domain}/{transfer_set_name}")
            return True
        except Exception as e:
            self.logger.debug(f"Failed to send Transfer_Report_NACK: {e}")
            return False
