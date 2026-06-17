"""
HART Security Mixin

Handles security testing and authentication:
- Device lock state reading (Command 76)
- Lock/unlock operations (Command 71)
- Lock code brute-force
- Lock security analysis
- Comprehensive security analysis (write/calibration commands, encryption)
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any, Dict, List

if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


class SecurityMixin(_ScannerBase):
    """Mixin providing security testing and authentication operations."""

    def read_lock_state(self) -> int:
        """Read device lock state (Command 76).

        Returns:
            Lock state: 0=Unlocked, 1=Locked, 2=Permanently Locked,
                       -1=Unknown, -2=Not Supported
        """
        from ..scanner import LockState
        from ..hartip import HARTResponseCode, HARTIPTimeoutError

        client = self.client
        if not client:
            return LockState.UNKNOWN

        try:
            response = client.read_lock_state(self.poll_address)

            if response.response_code == HARTResponseCode.UNDEFINED_COMMAND:
                return LockState.NOT_SUPPORTED
            elif response.response_code == HARTResponseCode.CMD_NOT_IMPLEMENTED:
                return LockState.NOT_SUPPORTED

            if response.response_code == 0 and len(response.payload) >= 1:
                return response.payload[0]

        except (HARTIPTimeoutError, TimeoutError) as e:
            self.logger.debug(f"Failed to get response: {e}")
        except Exception as e:
            self.logger.debug(f"Error reading lock state: {e}")

        return LockState.UNKNOWN

    def try_unlock(self, lock_code: str) -> bool:
        """Attempt to unlock device with given lock code.

        Args:
            lock_code: Lock code to try (up to 8 characters)

        Returns:
            True if unlock successful
        """
        from ..hartip import HARTCommand, pack_ascii

        client = self.client
        if not client:
            return False

        try:
            # Build Command 71 (Lock Device) payload: lock_state(1) + packed_code(6)
            code_padded = lock_code[:8].ljust(8).upper()
            packed_code = pack_ascii(code_padded)
            # 0 = unlock
            data = bytes([0]) + packed_code
            response = client.send_command(
                HARTCommand.LOCK_DEVICE,  # Command 71
                self.poll_address,
                data,
            )
            return response.response_code == 0
        except Exception as e:
            self.logger.debug(f"Failed to get code_padded: {e}")
            return False

    def try_lock(self, lock_code: str) -> bool:
        """Lock device with given lock code.

        Args:
            lock_code: Lock code to set (up to 8 characters)

        Returns:
            True if lock successful
        """
        from ..hartip import HARTCommand, pack_ascii

        client = self.client
        if not client:
            return False

        try:
            # Build Command 71 (Lock Device) payload: lock_state(1) + packed_code(6)
            code_padded = lock_code[:8].ljust(8).upper()
            packed_code = pack_ascii(code_padded)
            # 1 = lock
            data = bytes([1]) + packed_code
            response = client.send_command(
                HARTCommand.LOCK_DEVICE,
                self.poll_address,
                data,
            )
            return response.response_code == 0
        except Exception as e:
            self.logger.debug(f"Failed to get code_padded: {e}")
            return False

    def bruteforce_lock(
        self,
        wordlist: str,
        delay: float = 0.1,
    ) -> Dict[str, Any]:
        """Attempt to unlock device using codes from file."""
        from ....utils.login_scanner import make_password_scanner
        from ..scanner import LockState

        if not self.client:
            return {"success": False, "error": "Not connected", "tested": 0}

        if not wordlist:
            return {"success": False, "error": "Wordlist file required", "tested": 0}

        lock_state = self.read_lock_state()
        if lock_state == LockState.NOT_SUPPORTED:
            return {"success": False, "error": "Device lock not supported (HART 5)", "tested": 0}
        elif lock_state == LockState.UNLOCKED:
            return {"success": True, "password": "(already unlocked)", "tested": 0}
        elif lock_state == LockState.PERMANENTLY_LOCKED:
            return {"success": False, "error": "Device is permanently locked", "tested": 0}

        def try_unlock_code(host: str, port: int, code: str) -> bool:
            return self.try_unlock(code)

        scanner = make_password_scanner(
            login_function=try_unlock_code, protocol="hart", rate_limit=delay
        )

        result = scanner(
            {
                "rhost": self.host,
                "rport": self.port,
                "wordlist": f"file:{wordlist}",
                "continue_on_success": False,
                "rate_limit": delay,
            }
        )

        return {
            "success": result.get("success", False),
            "password": result.get("password"),
            "tested": result.get("tested", 0),
        }

    def lock_security_analysis(self) -> List[Dict[str, Any]]:
        """Analyze device lock security."""
        from ..scanner import LockState

        findings = []

        if not self.client:
            return [{"severity": "error", "issue": "Not connected"}]

        lock_state = self.read_lock_state()

        if lock_state == LockState.NOT_SUPPORTED:
            findings.append(
                {
                    "id": "HART-LOCK-001",
                    "severity": "info",
                    "issue": "Device lock not supported",
                    "description": "Device does not support lock feature (likely HART 5)",
                }
            )
        elif lock_state == LockState.UNLOCKED:
            findings.append(
                {
                    "id": "HART-LOCK-002",
                    "severity": "high",
                    "issue": "Device lock disabled",
                    "description": "Device is not locked - configuration can be changed",
                    "recommendation": "Enable device lock via Command 77",
                }
            )
        elif lock_state == LockState.LOCKED:
            findings.append(
                {
                    "id": "HART-LOCK-003",
                    "severity": "info",
                    "issue": "Device lock enabled",
                    "description": "Device is locked - configuration protected",
                }
            )

            quick_codes = ["", "00000000", "12345678"]
            for code in quick_codes:
                if self.try_unlock(code):
                    findings.append(
                        {
                            "id": "HART-LOCK-004",
                            "severity": "critical",
                            "issue": "Default lock code in use",
                            "description": (
                                f"Device unlocked with default code: "
                                f"'{code if code else '(empty)'}'"
                            ),
                            "recommendation": "Change lock code to a strong, unique value",
                        }
                    )
                    break
                time.sleep(0.1)

        elif lock_state == LockState.PERMANENTLY_LOCKED:
            findings.append(
                {
                    "id": "HART-LOCK-005",
                    "severity": "info",
                    "issue": "Device permanently locked",
                    "description": "Device is permanently locked - cannot be unlocked",
                }
            )

        return findings

    def security_analysis(self) -> List[Dict[str, Any]]:
        """Perform security analysis of HART device."""
        from ..hartip import HARTResponseCode

        findings = []

        if not self.client:
            return [{"severity": "error", "issue": "Not connected"}]

        findings.append(
            {
                "severity": "high",
                "issue": "No authentication",
                "description": "HART protocol has no authentication mechanism. "
                "Anyone with network access can read/write device.",
            }
        )

        write_commands = [
            (6, "Write Polling Address"),
            (17, "Write Message"),
            (18, "Write Tag/Descriptor/Date"),
            (19, "Write Final Assembly Number"),
            (35, "Write Primary Variable Range"),
            (44, "Write Primary Variable Units"),
            (45, "Trim Loop Current Zero"),
            (46, "Trim Loop Current Gain"),
            (50, "Write Damping Value"),
        ]

        for cmd, name in write_commands:
            try:
                response = self.client.send_command(cmd, self.poll_address, b"")
                if response.response_code not in [
                    HARTResponseCode.UNDEFINED_COMMAND,
                    HARTResponseCode.CMD_NOT_IMPLEMENTED,
                ]:
                    findings.append(
                        {
                            "severity": "medium",
                            "issue": f"Write command accessible: {name}",
                            "description": f"Command {cmd} ({name}) is accessible and may allow "
                            "configuration changes.",
                            "command": cmd,
                        }
                    )
            except Exception as e:
                self.logger.debug(f"Failed to get response: {e}")

        dangerous_commands = [
            (42, "Master Reset"),
            (43, "Set Device Variable Zero"),
            (45, "Trim Loop Current Zero"),
            (46, "Trim Loop Current Gain"),
        ]

        for cmd, name in dangerous_commands:
            try:
                response = self.client.send_command(cmd, self.poll_address, b"")
                if response.response_code not in [
                    HARTResponseCode.UNDEFINED_COMMAND,
                    HARTResponseCode.CMD_NOT_IMPLEMENTED,
                    HARTResponseCode.IN_WRITE_PROTECT_MODE,
                ]:
                    findings.append(
                        {
                            "severity": "critical",
                            "issue": f"Dangerous command accessible: {name}",
                            "description": f"Command {cmd} ({name}) could cause device malfunction "
                            "or calibration loss.",
                            "command": cmd,
                        }
                    )
            except Exception as e:
                self.logger.debug(f"Failed to get response: {e}")

        try:
            response = self.client.send_command(38, self.poll_address, b"")
            if response.response_code == HARTResponseCode.IN_WRITE_PROTECT_MODE:
                findings.append(
                    {
                        "severity": "info",
                        "issue": "Write protect enabled",
                        "description": "Device has write protection enabled, "
                        "limiting remote configuration changes.",
                    }
                )
            else:
                findings.append(
                    {
                        "severity": "high",
                        "issue": "Write protect disabled",
                        "description": "Device does not have write protection enabled. "
                        "Configuration can be modified remotely.",
                    }
                )
        except Exception as e:
            self.logger.debug(f"Failed to get response: {e}")

        # HART-SEC-010: v1-no-TLS finding
        if self.server_version == 1:
            findings.append(
                {
                    "id": "HART-SEC-010",
                    "severity": "high",
                    "issue": "HART-IP v1 server (no TLS support)",
                    "description": "Server only supports HART-IP v1 (plaintext). "
                    "All communication is unencrypted and unauthenticated.",
                    "recommendation": "Upgrade to HART-IP v2 with TLS/PSK support",
                }
            )

        # HART-SEC-011: Check extended device status for anomalies
        try:
            additional_status = self.read_additional_status()
            decoded = additional_status.get("extended_device_status_decoded", {})
            if decoded:
                alerts = [k for k, v in decoded.items() if v]
                if alerts:
                    findings.append(
                        {
                            "id": "HART-SEC-011",
                            "severity": "medium",
                            "issue": "Device status flags active",
                            "description": f"Active status flags: {', '.join(alerts)}",
                        }
                    )
        except Exception as e:
            self.logger.debug(f"Failed to get additional_status: {e}")

        return findings
