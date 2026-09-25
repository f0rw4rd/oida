"""
Snap7 Security Mixin

Handles security assessment and authentication:
- CPU protection level checking
- PUT/GET access detection for S7-1200/1500
- Password authentication and session management
- Password brute-force with rate limiting
- Null/empty password testing
- Security analysis aggregation
- Write access testing
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, Optional


if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


class SecurityMixin(_ScannerBase):
    """Mixin providing security assessment and authentication operations."""

    def _check_protection_level(self, connection: Any) -> Optional[Dict[str, Any]]:
        """Check CPU protection level - returns detailed protection info"""
        self.logger.debug("Checking CPU protection level...")
        try:
            protection = connection.get_protection()

            # S7Protection is a struct with 5 fields (ushort each)
            protection_info = {
                "sch_schal": protection.sch_schal,  # Mode selector protection
                "sch_par": protection.sch_par,  # Parameter protection
                "sch_rel": protection.sch_rel,  # Release protection
                "bart_sch": protection.bart_sch,  # Operator control
                "anl_sch": protection.anl_sch,  # Analog protection
            }

            # Determine overall protection level.
            #
            # IMPORTANT: an all-zero S7Protection struct (every field == 0)
            # is NOT a valid "no protection" verdict - python-snap7's
            # get_protection() commonly returns a zeroed struct on
            # S7-1200/1500 firmware that does not expose this SZL, or when
            # the read fails silently. Reporting level=1 / "Full access"
            # in that case produced a false-positive CRITICAL finding on
            # every modern CPU. Treat all-zero as INDETERMINATE instead.
            has_protection = any(protection_info.values())
            all_zero = all(v == 0 for v in protection_info.values())

            # In the S7 protection encoding the field value IS the
            # protection level (1 = no protection / full read+write without
            # password, 2 = write-protected, 3 = read/write protected).
            # Mirror SZLParser._parse_0x0132: take the strongest level
            # advertised across the protection-relevant fields.
            level = max(
                protection_info["sch_schal"],
                protection_info["sch_par"],
                protection_info["sch_rel"],
            )

            if all_zero:
                level = 0
                desc = "Indeterminate (CPU did not expose protection SZL)"
            elif level == 1:
                # level 1 = no protection (open PLC). _analyze_security keys
                # the "No protection" concern off this exact value, so keep
                # the two in lock-step (== 1, not <= 1).
                desc = "No protection - Full read/write access"
            elif level == 2:
                desc = "Read access - Write protected"
            else:
                desc = "Full protection - Password required"

            self.logger.display(f"Protection Level: {level} - {desc}")
            for field, value in protection_info.items():
                if value:
                    self.logger.debug(f"    {field}: {value}")

            return {
                "level": level,
                "description": desc,
                "has_protection": has_protection,
                "indeterminate": all_zero,
                "fields": protection_info,
            }

        except Exception as e:
            self.logger.debug(f"Error checking protection level: {e}")
            return None

    def _detect_put_get_access(self, connection: Any, series: str = "") -> Dict[str, Any]:
        """
        Detect if PUT/GET communication is enabled on S7-1200/1500.

        PUT/GET is a TIA Portal setting that allows external clients to
        read/write PLC memory without S7CommPlus authentication.

        Detection method:
        - Try to read 1 byte from Markers area (M0)
        - If read succeeds -> PUT/GET is ENABLED
        - If "function refused" / "CPU refused" -> PUT/GET is DISABLED
        - Connection alone is not enough - must test actual memory access

        Returns:
            Dict with: enabled (bool), method (str), details (str)
        """
        from oida.protocols.snap7.scanner import _get_snap7_client, _suppress_snap7_logging

        self.logger.debug("Detecting PUT/GET access for series=%s...", series)
        result = {
            "enabled": None,
            "details": "",
        }

        # Only relevant for S7-1200/1500
        if series and series not in ("S7-1200", "S7-1500"):
            result["details"] = f"{series} - PUT/GET not applicable"
            return result

        if not connection or not connection.get_connected():
            result["details"] = "No active connection"
            return result

        with _suppress_snap7_logging():
            try:
                # Try to read 1 byte from Markers area (M0)
                # This is the most reliable test for PUT/GET access
                snap7_client = _get_snap7_client()
                _data = connection.read_area(snap7_client.Area.MK, 0, 0, 1)  # noqa: F841

                # If we get here, read succeeded -> PUT/GET is ENABLED
                result["enabled"] = True
                result["details"] = "PUT/GET ENABLED - Memory read succeeded"

                self.logger.warning("PUT/GET communication is ENABLED")
                self.logger.display("    Snap7/HMI clients can read/write PLC data")
                self.logger.display(
                    "    Disable in TIA Portal: Protection -> Connection mechanisms"
                )

                # Log security finding
                self.logger.security_finding(
                    "Insecure configuration",
                    detail="put_get_enabled",
                )

            except Exception as e:
                error_msg = str(e).lower()
                error_bytes = str(e)

                # Check for "function refused" or "CPU refused" - means PUT/GET is disabled
                if "refused" in error_msg or "access denied" in error_msg:
                    result["enabled"] = False
                    result["details"] = "PUT/GET DISABLED - Memory access refused"
                    self.logger.success("PUT/GET communication is DISABLED (secure)")
                else:
                    # Other errors (timeout, connection issues, etc.)
                    self.logger.debug(f"PUT/GET detection inconclusive: {e}")
                    result["details"] = f"Detection inconclusive: {error_bytes}"

        return result

    # =========================================================================
    # Password Authentication Methods
    # =========================================================================

    def clear_session(self, connection: Any) -> None:
        """Clear password session (logout)"""
        try:
            connection.clear_session_password()
        except Exception as e:
            self.logger.debug("clear session failed: %s", e)  # ignore; may fail on some PLCs

    def bruteforce_password(
        self,
        connection: Any,
        wordlist_path: Optional[str] = None,
        rate_limit: float = 0.5,
        continue_on_success: bool = False,
    ) -> Dict[str, Any]:
        """Brute force password using wordlist or defaults

        Args:
            connection: S7 connection object
            wordlist_path: Path to password file, or None to use defaults
            rate_limit: Delay between attempts in seconds (default 0.5)
            continue_on_success: Keep testing after the first valid password (default: stop)
        """
        import time

        from oida.utils.login_scanner import format_wordlist_source, load_passwords
        from oida.utils import ProgressTracker
        from oida.utils.protocol_helpers import (
            MAX_CONSECUTIVE_CONNECTION_ERRORS,
            is_connection_error,
        )
        from oida.protocols.snap7.scanner import _suppress_snap7_logging

        results: Dict[str, Any] = {
            "success": False,
            "password": None,
            "attempts": 0,
            "found": [],
            "connection_errors": 0,
            "aborted": False,
        }

        with _suppress_snap7_logging():
            # Load passwords: wordlist file > protocol defaults
            source = f"file:{wordlist_path}" if wordlist_path else None
            passwords = load_passwords(source, protocol="s7")

            if not passwords:
                self.logger.fail("No passwords to test (wordlist empty or not found)")
                return results

            source = format_wordlist_source(wordlist_path)
            self.logger.display(
                f"Starting brute force with {len(passwords)} passwords from {source}..."
            )
            progress = ProgressTracker(len(passwords), logger=self.logger)
            consecutive_connection_errors = 0

            for password in passwords:
                # S7 passwords are max 8 chars
                test_password = password[:8] if len(password) > 8 else password

                try:
                    connection.set_session_password(test_password)
                    # Test if password worked by reading protected data
                    connection.get_cpu_state()

                    # Success!
                    results["attempts"] += 1
                    consecutive_connection_errors = 0
                    progress.success += 1
                    results["success"] = True
                    results["password"] = test_password
                    results["found"].append(test_password)
                    self.logger.security_finding(
                        "Weak password",
                        detail=f"S7 password found: {test_password}",
                    )

                    # Report to framework (S7 uses password-only, no username)
                    host, port = self.get_target_info()
                    self.report_credential("", test_password, host=host, port=port)

                    if not continue_on_success:
                        progress.update()
                        break

                except Exception as e:
                    if is_connection_error(e):
                        # Lost the connection to the PLC: this password was
                        # never actually tested against the device.
                        results["connection_errors"] += 1
                        consecutive_connection_errors += 1
                        self.logger.debug(
                            f"    NOT tested (connection error): {test_password} -> {e}"
                        )
                        self.clear_session(connection)
                        if consecutive_connection_errors >= MAX_CONSECUTIVE_CONNECTION_ERRORS:
                            results["aborted"] = True
                            progress.update()
                            self.logger.fail(
                                f"PLC unreachable after {consecutive_connection_errors} "
                                f"consecutive connection failures -- aborting brute force. "
                                f"{results['attempts']} of {len(passwords)} passwords were "
                                f"actually tested."
                            )
                            break
                    else:
                        # Wrong password - continue
                        results["attempts"] += 1
                        consecutive_connection_errors = 0
                        progress.failed += 1
                        self.logger.debug(f"    {test_password}")
                        self.clear_session(connection)

                progress.update()

                # Rate limiting to avoid lockout
                if rate_limit > 0:
                    time.sleep(rate_limit)

            progress.finish()

            if results["connection_errors"] and not results["aborted"]:
                self.logger.warning(
                    f"{results['connection_errors']} password(s) were skipped because the "
                    f"PLC could not be reached -- they were NOT tested."
                )
            if not results["success"] and not results["aborted"]:
                self.logger.warning(f"Password not found after {results['attempts']} attempts")

        return results

    def test_null_password(self, connection: Any) -> Dict[str, Any]:
        """Test null/empty password access"""
        results = {
            "success": False,
            "password": None,
            "vulnerable": False,
        }

        self.logger.display("Testing null/empty password access...")

        try:
            # Try empty password
            connection.set_session_password("")
            # Verify by reading protected data
            connection.get_cpu_state()

            results["success"] = True
            results["password"] = ""
            results["vulnerable"] = True
            self.logger.success("VULNERABLE: Empty password accepted!")

            # Report to framework
            host, port = self.get_target_info()
            self.report_credential("", "", host=host, port=port)

            # Report security finding
            self.logger.security_finding(
                "No authentication",
                detail="Empty password accepted",
            )

        except Exception as e:
            self.logger.debug(f"Empty password rejected: {e}")
            self.clear_session(connection)

        return results

    def _analyze_security(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze security configuration"""
        from oida.utils import SecurityAnalyzer

        self.logger.debug("Analyzing security configuration")
        protection_data = results.get("protection_level")
        # Extract level from dict if needed (protection_level can be dict or int)
        if isinstance(protection_data, dict):
            protection_level = protection_data.get("level", 3)
        elif protection_data is None:
            protection_level = 3  # Default to most restrictive if unknown
        else:
            protection_level = protection_data

        analysis = SecurityAnalyzer.assess_protocol_security(
            {
                "authentication": self.password != "",  # Password was provided
                "authorization": protection_level > 1,  # Some protection enabled
                "encryption": False,  # S7 protocol is not encrypted
                "integrity_check": False,  # No integrity checking
                "access_control": protection_level == 3,  # Full protection
            }
        )

        # Report no encryption (S7 protocol is never encrypted)
        self.logger.security_finding(
            "No encryption",
            detail="S7 protocol does not support encryption",
        )

        # Add S7 specific concerns
        analysis["concerns"] = []

        # protection_level == 0 == indeterminate (see _check_protection_level
        # comment). Do NOT emit a finding when the CPU didn't expose the
        # SZL - we can't tell the difference between "no protection" and
        # "we couldn't read it".
        if protection_level == 1:
            analysis["concerns"].append("No protection - Full read/write access")
            self.logger.security_finding(
                "Insecure configuration",
                detail="protection_level=1",
            )
        elif protection_level == 2:
            analysis["concerns"].append("Write protection only - Read access available")
            self.logger.security_finding(
                "Insecure configuration",
                detail="protection_level=2",
            )

        db_count = len(results.get("data_blocks", []))
        if db_count > 0:
            analysis["concerns"].append(f"{db_count} data blocks accessible")

        writable_areas = [
            area for area, info in results.get("memory_areas", {}).items() if info.get("writable")
        ]
        if writable_areas:
            analysis["concerns"].append(f"Writable memory areas: {', '.join(writable_areas)}")

        return analysis

    def _test_write_access(self, conn: Any) -> Dict[str, Any]:
        """Test write access by reading a value and writing it back unchanged."""
        from oida.protocols.snap7.constants import S7MemoryArea

        result = {"writable_areas": [], "read_only": True}
        # Test markers area (safest to test)
        try:
            data = bytes(conn.read_area(S7MemoryArea.MK, 0, 0, 1))
            conn.write_area(S7MemoryArea.MK, 0, 0, bytearray(data))
            result["writable_areas"].append("markers")
            result["read_only"] = False
        except Exception as e:
            self.logger.debug(f"S7 markers area read/write probe failed: {e}")
        # Test outputs area
        try:
            data = bytes(conn.read_area(S7MemoryArea.PA, 0, 0, 1))
            conn.write_area(S7MemoryArea.PA, 0, 0, bytearray(data))
            result["writable_areas"].append("outputs")
            result["read_only"] = False
        except Exception as e:
            self.logger.debug(f"S7 outputs area read/write probe failed: {e}")
        return result

    def test_write_access_action(self, conn: Any) -> Dict[str, Any]:
        """Test write access (CLI action wrapper). Writes each probed value back
        unchanged, but still issues active write PDUs against the PLC."""
        result = self._test_write_access(conn)
        writable = result.get("writable_areas", [])
        if writable:
            self.logger.security_finding(
                "Writable access",
                detail=f"S7 memory areas are writable: {', '.join(writable)}",
            )
            for area in writable:
                self.logger.display(f"    WRITABLE: {area} area")
        else:
            self.logger.success("No writable memory areas detected (read-only)")
        return {"success": True, **result}
