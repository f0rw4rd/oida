"""
HART Fuzz Mixin

Handles fuzzing and write operations:
- Command fuzzing with radamsa or basic payloads
- Poll address writing (Command 6)
- Tag/descriptor/date writing (Command 18)
- Message writing (Command 17)
- Self-test (Command 41)
- Config flag reset (Command 38)
- Master reset (Command 42)
- Raw command sending
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any, Dict, List, Tuple

import logging

logger = logging.getLogger(__name__)


if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


class FuzzMixin(_ScannerBase):
    """Mixin providing fuzzing and write operations."""

    def fuzz_commands(self, iterations: int = 20, command_list: List[int] = None) -> Dict[str, Any]:
        """Fuzz HART commands with malformed data."""
        from ..hartip import HARTResponseCode, HARTIPTimeoutError
        from ....utils.lazy_import import lazy_import

        _fuzzer = lazy_import("oida.utils.fuzzer", "fuzzer")

        if not self.client:
            return {"error": "Not connected"}

        if command_list is None:
            command_list = [0, 1, 2, 3, 6, 11, 12, 13, 15, 17, 18, 42, 48]

        results: Dict[str, Any] = {
            "tested": 0,
            "commands_fuzzed": [],
            "anomalies": [],
            "errors": [],
        }

        if not _fuzzer.is_available:
            return self._basic_fuzz(iterations, command_list)
        fuzz = _fuzzer.fuzz

        for cmd in command_list:
            cmd_stats = {"command": cmd, "iterations": 0, "anomalies": 0}

            try:
                baseline = self.client.send_command(cmd, self.poll_address, b"")
                baseline_code = baseline.response_code
            except Exception:
                baseline_code = None

            base_payloads = [b"", b"\x00" * 10, b"\xff" * 10, b"\x00\x01\x02\x03\x04"]

            for base_payload in base_payloads:
                for i, payload in enumerate(
                    fuzz(base_payload, count=iterations // len(base_payloads))
                ):
                    try:
                        response = self.client.send_command(cmd, self.poll_address, payload)
                        cmd_stats["iterations"] += 1
                        results["tested"] += 1

                        if baseline_code is not None:
                            if response.response_code not in [
                                baseline_code,
                                HARTResponseCode.TOO_FEW_DATA_BYTES,
                                HARTResponseCode.PARAMETER_TOO_LARGE,
                                HARTResponseCode.PARAMETER_TOO_SMALL,
                                HARTResponseCode.INVALID_SELECTION,
                            ]:
                                cmd_stats["anomalies"] += 1
                                results["anomalies"].append(
                                    {
                                        "command": cmd,
                                        "payload": payload.hex()[:32],
                                        "response_code": response.response_code,
                                    }
                                )

                    except (HARTIPTimeoutError, TimeoutError):
                        results["anomalies"].append(
                            {
                                "command": cmd,
                                "payload": payload.hex()[:32],
                                "error": "timeout",
                            }
                        )
                        try:
                            self.client.close()
                            time.sleep(1)
                            self.client.connect()
                        except Exception:
                            break

                    except Exception as e:
                        results["errors"].append({"command": cmd, "error": str(e)})

                    time.sleep(0.05)

            results["commands_fuzzed"].append(cmd_stats)

        return results

    def _basic_fuzz(self, iterations: int, command_list: List[int]) -> Dict[str, Any]:
        """Basic fuzzing without radamsa"""
        from ..hartip import HARTIPTimeoutError

        results: Dict[str, Any] = {
            "tested": 0,
            "commands_fuzzed": [],
            "anomalies": [],
            "errors": [],
        }

        fuzz_payloads = [
            b"",
            b"\x00",
            b"\xff",
            b"\x00" * 50,
            b"\xff" * 50,
            b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09",
            b"\xff\xfe\xfd\xfc\xfb\xfa\xf9\xf8\xf7\xf6",
            bytes(range(256)),
        ]

        for cmd in command_list:
            cmd_stats = {"command": cmd, "iterations": 0, "anomalies": 0}

            for payload in fuzz_payloads[:iterations]:
                try:
                    self.client.send_command(cmd, self.poll_address, payload)
                    cmd_stats["iterations"] += 1
                    results["tested"] += 1
                except (HARTIPTimeoutError, TimeoutError):
                    results["anomalies"].append(
                        {
                            "command": cmd,
                            "payload": payload.hex()[:32],
                            "error": "timeout",
                        }
                    )
                except Exception as e:
                    results["errors"].append({"command": cmd, "error": str(e)})

            results["commands_fuzzed"].append(cmd_stats)

        return results

    def write_poll_address(self, new_address: int) -> bool:
        """Write new polling address (Command 6).

        Args:
            new_address: New polling address (0-15)
        """
        if not self.client:
            return False

        try:
            # Library signature: write_poll_address(poll_address, loop_current_mode=0, address=0)
            # poll_address = new address, address = current address for the request
            response = self.client.write_poll_address(new_address, address=self.poll_address)
            return response.response_code == 0
        except Exception as e:
            logger.debug(f"Failed to get response: {e}")
            return False

    def write_tag(self, tag: str, descriptor: str = "", date: Tuple[int, int, int] = None) -> bool:
        """Write tag, descriptor, and date (Command 18).

        Args:
            tag: Device tag (max 8 characters, packed ASCII)
            descriptor: Device descriptor (max 16 characters, packed ASCII)
            date: Tuple of (day, month, year) or None for current date
        """
        if not self.client:
            return False

        try:
            if date:
                day, month, year = date
            else:
                import datetime

                now = datetime.datetime.now()
                day, month, year = now.day, now.month, now.year % 100 + 100

            # Library signature: write_tag_descriptor_date(tag, descriptor, day, month, year, address=0)
            response = self.client.write_tag_descriptor_date(
                tag, descriptor, day, month, year, address=self.poll_address
            )
            return response.response_code == 0
        except Exception as e:
            logger.debug(f"if date:: {e}")
            return False

    def write_message(self, message: str) -> bool:
        """Write device message (Command 17).

        Args:
            message: Device message (max 24 characters, packed ASCII)
        """
        if not self.client:
            return False

        try:
            response = self.client.write_message(message, address=self.poll_address)
            return response.response_code == 0
        except Exception as e:
            logger.debug(f"Failed to get response: {e}")
            return False

    def perform_self_test(self) -> bool:
        """Perform device self-test (Command 41)."""
        if not self.client:
            return False

        try:
            response = self.client.perform_self_test(self.poll_address)
            return response.response_code == 0
        except Exception as e:
            logger.debug(f"Failed to get response: {e}")
            return False

    def reset_config_flag(self) -> bool:
        """Reset configuration changed flag (Command 38)."""
        from ..hartip import HARTCommand

        if not self.client:
            return False

        try:
            response = self.client.send_command(HARTCommand.RESET_CONFIG_FLAG, self.poll_address)
            return response.response_code == 0
        except Exception as e:
            logger.debug(f"Failed to get response: {e}")
            return False

    def perform_master_reset(self) -> bool:
        """Perform master reset (Command 42). WARNING: Resets to factory defaults."""
        from ..hartip import HARTCommand

        if not self.client:
            return False

        try:
            self.client.perform_self_test(self.poll_address)
            response = self.client.send_command(HARTCommand.PERFORM_MASTER_RESET, self.poll_address)
            return response.response_code == 0
        except Exception as e:
            logger.debug(f"self.client.perform_self_test(self.po...: {e}")
            return False

    def send_raw_command(self, command: int, data: bytes = b"") -> Dict[str, Any]:
        """Send raw HART command with optional data payload."""
        from ..hartip import HARTResponseCode

        if not self.client:
            return {"success": False, "error": "Not connected"}

        try:
            response = self.client.send_command(command, self.poll_address, data)
            try:
                code_name = HARTResponseCode(response.response_code).name
            except ValueError:
                code_name = f"Unknown ({response.response_code})"
            return {
                "success": response.response_code == 0,
                "command": command,
                "response_code": response.response_code,
                "response_code_name": code_name,
                "device_status": response.device_status,
                "payload": response.payload.hex() if response.payload else "",
                "payload_length": len(response.payload) if response.payload else 0,
            }
        except Exception as e:
            return {"success": False, "command": command, "error": str(e)}
