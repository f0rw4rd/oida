"""
HART Security Mixin

Handles security testing and authentication:
- Device lock state reading (Command 76)
- Lock/unlock operations (Command 71)
- Lock code brute-force
- Comprehensive security analysis (write/calibration commands, encryption)
"""

from __future__ import annotations

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
        from oida.protocols.hart.scanner import LockState
        from oida.protocols.hart.hartip import HARTResponseCode, HARTIPTimeoutError

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
        from oida.protocols.hart.hartip import HARTCommand, pack_ascii

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
            self.logger.debug(f"Unlock (cmd 71) send failed: {e}")
            return False

    def try_lock(self, lock_code: str) -> bool:
        """Lock device with given lock code.

        Args:
            lock_code: Lock code to set (up to 8 characters)

        Returns:
            True if lock successful
        """
        from oida.protocols.hart.hartip import HARTCommand, pack_ascii

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
            self.logger.debug(f"Lock (cmd 71) send failed: {e}")
            return False

    def bruteforce_lock(
        self,
        wordlist: str,
        delay: float = 0.1,
    ) -> Dict[str, Any]:
        """Attempt to unlock device using codes from file."""
        from oida.utils.login_scanner import make_password_scanner
        from oida.protocols.hart.scanner import LockState

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

    def security_analysis(self, probe_categories=None) -> List[Dict[str, Any]]:
        """Perform security analysis of HART device.

        Args:
            probe_categories: which mutating command groups to actually transmit
                under --confirm. None (default, e.g. --security/full) probes all
                groups. Otherwise a subset of {"write", "dangerous"} so a
                category-scoped caller (--probe-write vs --probe-calibration)
                only puts its own commands on the wire -- e.g. --probe-write
                must not transmit Cmd 42 Master Reset.
        """
        from oida.protocols.hart.hartip import HARTResponseCode

        findings = []

        if not self.client:
            return [{"issue": "Not connected"}]

        probe_all = probe_categories is None
        probe_write = probe_all or "write" in probe_categories
        probe_dangerous = probe_all or "dangerous" in probe_categories

        findings.append(
            {
                "issue": "No authentication",
                "description": "HART protocol has no authentication mechanism. "
                "Anyone with network access can read/write device.",
            }
        )

        # Probing write/calibration commands (6/17/18/.../42 Master Reset,
        # 45/46 trim) transmits real mutating commands to live instrumentation.
        # Sending an empty payload may still be accepted by some devices, so
        # these accessibility probes are gated behind --confirm exactly like the
        # named write / master-reset / fuzz paths. Without --confirm the analysis
        # is limited to non-mutating reachability/status reads below.
        if self.confirm and probe_write:
            write_commands = [
                (6, "Write Polling Address"),
                (17, "Write Message"),
                (18, "Write Tag/Descriptor/Date"),
                (19, "Write Final Assembly Number"),
                (35, "Write Primary Variable Range"),
                (44, "Write Primary Variable Units"),
                (45, "Trim Loop Current Zero"),
                (46, "Trim Loop Current Gain"),
                (34, "Write Damping Value"),
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
                                "issue": f"Write command accessible: {name}",
                                "description": f"Command {cmd} ({name}) is accessible and may allow "
                                "configuration changes.",
                                "command": cmd,
                            }
                        )
                except Exception as e:
                    self.logger.debug(f"Write-command probe (cmd {cmd}) failed: {e}")

        if self.confirm and probe_dangerous:
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
                                "issue": f"Dangerous command accessible: {name}",
                                "description": f"Command {cmd} ({name}) could cause device "
                                "malfunction or calibration loss.",
                                "command": cmd,
                            }
                        )
                except Exception as e:
                    self.logger.debug(f"Dangerous-command probe (cmd {cmd}) failed: {e}")

        if not self.confirm:
            findings.append(
                {
                    "issue": "Write/calibration accessibility probes skipped",
                    "description": "Active probing of write and dangerous commands "
                    "(Cmd 6/17/18/42 Master Reset, 45/46 trim) requires --confirm. "
                    "Re-run with --confirm to test command accessibility against this device.",
                }
            )

        # Cmd 38 (Reset Config Changed Flag) is itself a mutating write; probe it
        # only under --confirm and only when the write group is in scope (it is
        # used here purely to detect write-protect via IN_WRITE_PROTECT_MODE).
        if self.confirm and probe_write:
            try:
                response = self.client.send_command(38, self.poll_address, b"")
                if response.response_code == HARTResponseCode.IN_WRITE_PROTECT_MODE:
                    findings.append(
                        {
                            "issue": "Write protect enabled",
                            "description": "Device has write protection enabled, "
                            "limiting remote configuration changes.",
                        }
                    )
                else:
                    findings.append(
                        {
                            "issue": "Write protect disabled",
                            "description": "Device does not have write protection enabled. "
                            "Configuration can be modified remotely.",
                        }
                    )
            except Exception as e:
                self.logger.debug(f"Write-protect probe (cmd 38) failed: {e}")

        # HART-SEC-010: v1-no-TLS finding
        if self.server_version == 1:
            findings.append(
                {
                    "id": "HART-SEC-010",
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
                            "issue": "Device status flags active",
                            "description": f"Active status flags: {', '.join(alerts)}",
                        }
                    )
        except Exception as e:
            self.logger.debug(f"Failed to get additional_status: {e}")

        return findings
