"""
Modbus Monitor Mixin

Handles register monitoring mode for real-time value observation.
"""

from __future__ import annotations

import time
from datetime import datetime
from typing import TYPE_CHECKING, Dict, List

if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase

    from ..cli_runner import modbus
else:
    _ScannerBase = object


class MonitorMixin(_ScannerBase):
    """Mixin providing Modbus register monitoring operations."""

    def _handle_monitor(self):
        """Handle --monitor flag for real-time register watching."""
        if not getattr(self.args, "monitor", False):
            return

        scan_range = getattr(self.args, "scan_range", None)
        if not scan_range:
            self.logger.fail("--monitor requires --scan-range / -r")
            return

        interval = getattr(self.args, "interval", 1.0)
        duration = getattr(self.args, "duration", 0)  # 0 = infinite
        on_change = getattr(self.args, "on_change", False)
        log_file = getattr(self.args, "log_file", None)
        register_type = getattr(self.args, "register_type", "holding")

        self.logger.display(f"Monitoring registers {scan_range} (interval: {interval}s)")
        if duration:
            self.logger.display(f"Duration: {duration}s")
        if on_change:
            self.logger.display("Mode: on-change only")

        # Parse range
        addresses = self._parse_register_range(scan_range)
        if not addresses:
            self.logger.fail("Invalid register range")
            return

        # Open log file if specified
        log_handle = None
        if log_file:
            try:
                log_handle = open(log_file, "a")
                log_handle.write(f"# Modbus Monitor Log - Started {datetime.now().isoformat()}\n")
                log_handle.write(
                    f"# Target: {self.host}:{self.port}, Unit: {self.scanner.unit_id}\n"
                )
                log_handle.write("# timestamp,address,value\n")
            except Exception as e:
                self.logger.warning(f"Could not open log file: {e}")

        previous_values = {}
        start_time = time.time()
        iteration = 0

        try:
            while True:
                iteration += 1
                current_time = time.time()

                # Check duration limit
                if duration and (current_time - start_time) >= duration:
                    self.logger.display("Monitor duration reached")
                    break

                # Read registers
                try:
                    values = self._read_register_batch(addresses, register_type)
                except Exception as e:
                    self.logger.warning(f"Read error: {e}")
                    time.sleep(interval)
                    continue

                # Process and display
                timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
                changes = []

                for addr, value in values.items():
                    prev = previous_values.get(addr)

                    if on_change and prev == value:
                        continue

                    if prev is not None and prev != value:
                        changes.append((addr, prev, value))

                    previous_values[addr] = value

                    # Log to file
                    if log_handle:
                        log_handle.write(f"{datetime.now().isoformat()},{addr},{value}\n")
                        log_handle.flush()

                # Display output
                if not on_change or changes or iteration == 1:
                    if on_change and changes:
                        for addr, old, new in changes:
                            self.logger.display(f"[{timestamp}] Reg {addr}: {old} -> {new}")
                    elif not on_change:
                        # Show all values
                        val_str = " ".join(f"{a}={v}" for a, v in sorted(values.items())[:10])
                        if len(values) > 10:
                            val_str += f" (+{len(values) - 10} more)"
                        self.logger.display(f"[{timestamp}] {val_str}")

                time.sleep(interval)

        except KeyboardInterrupt:
            self.logger.display("Monitor stopped by user")
        finally:
            if log_handle:
                log_handle.close()

        self.results["data"]["monitor"] = {
            "iterations": iteration,
            "duration": time.time() - start_time,
            "final_values": previous_values,
        }

    def _parse_register_range(self, range_str: str) -> List[int]:
        """Parse register range string into a list of addresses (central parser)."""
        from ....utils import ProtocolParser

        return ProtocolParser.parse_address_range(range_str)

    def _read_register_batch(self: "modbus", addresses: List[int], reg_type: str) -> Dict[int, int]:
        """Read a batch of registers efficiently.

        Delegates to :func:`register_io.read_registers_batched`.
        """
        from ..register_io import read_registers_batched

        return read_registers_batched(
            self.conn,
            reg_type,
            addresses,
            unit_id=self.scanner.unit_id,
            fallback_individual=False,
        )
