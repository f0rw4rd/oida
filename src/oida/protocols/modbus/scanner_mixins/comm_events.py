"""
Modbus Scanner Communication Events Mixin

Handles FC 11/12 communication event operations:
- Get Comm Event Counter (FC 11)
- Get Comm Event Log (FC 12)
"""

from __future__ import annotations

from typing import Any, Dict, TYPE_CHECKING

if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


class ScannerCommEventsMixin(_ScannerBase):
    """Mixin providing FC 11/12 communication events for ModbusScanner."""

    def _read_comm_events(self, client: Any, count_only: bool = False) -> Dict[str, Any]:
        """
        Read communication event counter and log (FC 11/12)

        Args:
            client: Modbus client connection
            count_only: If True, only read FC 11 (event counter), skip FC 12 (event log)

        Returns:
            dict: Event counter and log information
        """
        from ..scanner import GenericPDU, execute_pdu

        events = {"counter": None, "log": None}

        # FC 11: Get Comm Event Counter
        try:
            pdu = GenericPDU(function_code=11)
            result = execute_pdu(client, pdu, self.unit_id)
            if not result.isError():
                events["counter"] = {
                    "status": getattr(result, "status", None),
                    "count": getattr(result, "count", None),
                }
        except Exception as e:
            self.logger.debug(f"FC11 (Event Counter) failed: {e}")

        # FC 12: Get Comm Event Log (skip if count_only)
        if not count_only:
            try:
                pdu = GenericPDU(function_code=12)
                result = execute_pdu(client, pdu, self.unit_id)
                if not result.isError():
                    events["log"] = {
                        "status": getattr(result, "status", None),
                        "event_count": getattr(result, "event_count", None),
                        "message_count": getattr(result, "message_count", None),
                        "events": list(getattr(result, "events", [])),
                    }
            except Exception as e:
                self.logger.debug(f"FC12 (Event Log) failed: {e}")

        return events
