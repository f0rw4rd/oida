"""
Modbus Scanner Diagnostics Mixin

Handles FC 8 diagnostic operations:
- Echo test (subfunction 0x00)
- Read diagnostic register (subfunction 0x02)
- Read/clear counters (subfunctions 0x0A-0x12)
"""

from __future__ import annotations

import time
from typing import Any, Dict, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


class ScannerDiagnosticsMixin(_ScannerBase):
    """Mixin providing FC 8 diagnostics for ModbusScanner."""

    def _run_diagnostics(
        self, client: Any, tests: str, diag_data: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Run Modbus diagnostics (Function Code 8)

        Args:
            client: Modbus client connection
            tests: Comma-separated tests or 'all'
                   Options: echo, counters, clear, restart, register, all
            diag_data: Optional hex string for echo test data (e.g. '0x1234')

        Returns:
            dict: Diagnostic results
        """

        results: Dict[str, Any] = {
            "supported": False,
            "echo_test": None,
            "diagnostic_register": None,
            "counters": {},
            "supported_subfunctions": [],
        }

        if tests is None or tests == "all":
            test_list = ["echo", "counters", "register"]
        else:
            test_list = tests.split(",")

        # Parse custom echo data if provided
        echo_data = 0x1234
        if diag_data:
            try:
                echo_data = int(diag_data, 16)
            except ValueError:
                self.logger.fail(
                    f"Invalid --diag-data value: {diag_data!r} (expected hex, e.g. 0x1234)"
                )
                return results

        # Echo test (subfunction 0x00)
        if "echo" in test_list:
            echo_result = self._diagnostic_echo_test(client, test_data=echo_data)
            if echo_result:
                results["echo_test"] = echo_result
                results["supported"] = True
                results["supported_subfunctions"].append(0x00)

        # Read diagnostic register (subfunction 0x02)
        if "register" in test_list:
            diag_reg = self._diagnostic_read_register(client)
            if diag_reg is not None:
                results["diagnostic_register"] = diag_reg
                results["supported_subfunctions"].append(0x02)

        # Read counters (subfunctions 0x0B-0x12)
        if "counters" in test_list:
            counters = self._diagnostic_read_counters(client)
            if counters:
                results["counters"] = counters
                results["supported_subfunctions"].extend(counters.keys())

        # Clear counters (subfunction 0x0A) - mutates device state.
        if "clear" in test_list:
            if not self._args_get("confirm", False):
                self.logger.fail(
                    "--diag clear runs subfunction 0x0A (Clear Counters and Diagnostic "
                    "Register) which mutates device state — requires --confirm"
                )
            else:
                clear_result = self._diagnostic_clear_counters(client)
                if clear_result:
                    results["clear_counters"] = clear_result
                    results["supported_subfunctions"].append(0x0A)

        # Restart communications (subfunction 0x01) - resets the listen-only
        # mode and clears communications event counters. Disruptive.
        if "restart" in test_list:
            if not self._args_get("confirm", False):
                self.logger.fail(
                    "--diag restart runs subfunction 0x01 (Restart Communications) "
                    "which resets device state — requires --confirm"
                )
            else:
                restart_result = self._diagnostic_restart(client)
                if restart_result:
                    results["restart"] = restart_result
                    results["supported_subfunctions"].append(0x01)

        return results

    def _args_get(self, key: str, default=None):
        """Pull a value from the scanner's args (which may be a dict or Namespace)."""
        args = getattr(self, "args", None)
        if args is None:
            return default
        if isinstance(args, dict):
            return args.get(key, default)
        return getattr(args, key, default)

    def _diagnostic_restart(self, client: Any) -> bool:
        """Restart Communications Option (subfunction 0x01)."""
        try:
            # pymodbus 3.x: diag_restart_communication(toggle, *, device_id).
            # toggle=False leaves the comms event log intact.
            result = client.diag_restart_communication(False, device_id=self.unit_id)
            return not result.isError()
        except Exception as e:
            self.logger.debug(f"Restart communications failed: {e}")
            return False

    def _diagnostic_echo_test(
        self, client: Any, test_data: int = 0x1234
    ) -> Optional[Dict[str, Any]]:
        """
        Perform diagnostic echo test (subfunction 0x00)

        Returns echo match and round-trip time
        """
        try:
            start_time = time.time()
            # Use pymodbus built-in diag_query_data method
            result = client.diag_query_data(msg=test_data, device_id=self.unit_id)
            rtt = (time.time() - start_time) * 1000  # ms

            if not result.isError():
                # pymodbus exposes the echoed payload on `.message`. Use it directly
                # (no `or` fallback): a valid 0x0000 echo is falsy and would otherwise
                # be discarded as None, reporting a spurious match=False. pymodbus 3.x
                # returns the echo as raw bytes (e.g. b"\x12\x34"); older notes claimed
                # an int. Normalize a 1-element tuple/list to its scalar and bytes to a
                # big-endian int before comparing against the int we sent.
                received = getattr(result, "message", None)
                normalized = received
                if isinstance(received, (tuple, list)) and len(received) == 1:
                    normalized = received[0]
                if isinstance(normalized, (bytes, bytearray)):
                    normalized = int.from_bytes(normalized, "big")
                return {
                    "sent": test_data,
                    "received": received,
                    "match": test_data == normalized,
                    "rtt_ms": round(rtt, 2),
                }
        except Exception as e:
            self.logger.debug(f"Echo test failed: {e}")
        return None

    @staticmethod
    def _normalize_diag_word(value: Any) -> Optional[int]:
        """Coerce a pymodbus diagnostic payload to a single 16-bit word.

        The device controls the response length, and pymodbus decodes >=4 data
        bytes into a *tuple* of words (and the echo sub-function into bytes).
        Callers format this with ``f"0x{...:04X}"``, which raises TypeError on
        anything but an int, so normalize here rather than at the display layer.
        """
        if isinstance(value, (tuple, list)):
            value = value[0] if value else None
        if isinstance(value, (bytes, bytearray)):
            value = int.from_bytes(value[:2], "big") if value else None
        if isinstance(value, bool) or not isinstance(value, int):
            return None
        return value & 0xFFFF

    def _diagnostic_read_register(self, client: Any) -> Optional[int]:
        """Read diagnostic register (subfunction 0x02)"""
        try:
            # Use pymodbus built-in diag_read_diagnostic_register method
            result = client.diag_read_diagnostic_register(device_id=self.unit_id)
            if not result.isError():
                raw = getattr(result, "message", None)
                if raw is None:
                    # A legitimate register value of 0 is falsy, so only fall
                    # back to `.data` when `.message` is genuinely absent.
                    raw = getattr(result, "data", 0)
                return self._normalize_diag_word(raw)
        except Exception as e:
            self.logger.debug(f"Read diagnostic register failed: {e}")
        return None

    def _diagnostic_read_counters(self, client: Any) -> Dict[int, Dict[str, Any]]:
        """Read all diagnostic counters (subfunctions 0x0B-0x12)"""
        from oida.protocols.modbus.constants import DIAGNOSTIC_SUBFUNCTIONS

        counters = {}
        # Map subfunctions to pymodbus client methods
        counter_methods = [
            (0x0B, "bus_message_count", "diag_read_bus_message_count"),
            (0x0C, "bus_comm_error_count", "diag_read_bus_comm_error_count"),
            (0x0D, "bus_exception_error_count", "diag_read_bus_exception_error_count"),
            (0x0E, "server_message_count", "diag_read_device_message_count"),
            (0x0F, "server_no_response_count", "diag_read_device_no_response_count"),
            (0x10, "server_nak_count", "diag_read_device_nak_count"),
            (0x11, "server_busy_count", "diag_read_device_busy_count"),
            (0x12, "bus_character_overrun_count", "diag_read_bus_char_overrun_count"),
        ]

        for subfunc, name, method_name in counter_methods:
            try:
                # Use pymodbus built-in diagnostic methods
                method = getattr(client, method_name, None)
                if method:
                    result = method(device_id=self.unit_id)
                    if not result.isError():
                        value = getattr(result, "message", None) or getattr(result, "data", 0)
                        counters[subfunc] = {
                            "name": name,
                            "description": DIAGNOSTIC_SUBFUNCTIONS.get(subfunc, "Unknown"),
                            "value": value,
                        }
            except Exception as e:
                self.logger.debug(f"Counter {name} read failed: {e}")

        return counters

    def _diagnostic_clear_counters(self, client: Any) -> bool:
        """Clear counters and diagnostic register (subfunction 0x0A)"""
        try:
            # Use pymodbus built-in diag_clear_counters method
            result = client.diag_clear_counters(device_id=self.unit_id)
            return not result.isError()
        except Exception as e:
            self.logger.debug(f"Clear counters failed: {e}")
        return False
