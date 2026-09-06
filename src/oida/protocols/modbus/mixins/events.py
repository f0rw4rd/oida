"""
Modbus Events Mixin

Handles communication event operations:
- Get Comm Event Counter (FC 11)
- Get Comm Event Log (FC 12)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


class EventsMixin(_ScannerBase):
    """Mixin providing Modbus communication event operations."""

    def _handle_events(self):
        """Handle communication events (FC 11/12)

        If --event-count-only is set, only reads FC 11 (event counter).
        Otherwise reads both FC 11 and FC 12 (event log).
        """
        count_only = getattr(self.args, "event_count_only", False)

        if count_only:
            self.logger.display("Reading event counter (FC 11 only)...")
        else:
            self.logger.display("Reading communication events...")

        events = self.scanner._read_comm_events(self.conn, count_only=count_only)
        self.results["data"]["events"] = events

        self.logger.display("[Communication Events]")
        if events.get("counter"):
            c = events["counter"]
            self.logger.display(
                f"  Event Counter: status={c.get('status')}, count={c.get('count')}"
            )
        if not count_only and events.get("log"):
            log = events["log"]
            evt_cnt, msg_cnt = log.get("event_count", 0), log.get("message_count", 0)
            self.logger.display(f"  Event Log: {evt_cnt} events, {msg_cnt} messages")
