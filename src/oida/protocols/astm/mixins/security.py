"""
ASTM Security Mixin

Handles protocol fuzzing and security analysis.
"""

import socket

from ..records import STX, ETX, ENQ, CR, LF


class SecurityMixin:
    """Mixin providing ASTM security operations."""

    def _fuzz_records(self):
        """Fuzz ASTM records and framing"""
        self.logger.display("Starting ASTM fuzzing...")

        iterations = getattr(self.args, "fuzz_iterations", 10)
        fuzz_record = getattr(self.args, "fuzz_record", None)
        fuzz_frame = getattr(self.args, "fuzz_frame", False)

        test_count = 0
        error_count = 0
        crash_count = 0

        fuzz_cases: list[tuple[str, bytes | str]] = []

        # Frame-level fuzzing
        if fuzz_frame:
            fuzz_cases.extend(
                [
                    ("empty_enq", b""),
                    ("double_enq", ENQ + ENQ),
                    ("enq_with_data", ENQ + b"GARBAGE"),
                    ("invalid_stx", b"\x01" + b"H|test" + ETX),
                    ("no_checksum", STX + b"1H|test" + ETX + CR + LF),
                    ("bad_checksum", STX + b"1H|test" + ETX + b"FF" + CR + LF),
                    (
                        "oversized_frame",
                        STX + b"1" + b"H|" + b"A" * 10000 + ETX + b"00" + CR + LF,
                    ),
                    ("null_bytes", STX + b"1H|\x00\x00\x00" + ETX + b"00" + CR + LF),
                ]
            )

        # Record-level fuzzing
        record_types = [fuzz_record] if fuzz_record else ["H", "P", "O", "R", "Q", "C"]

        for rec_type in record_types:
            fuzz_cases.extend(
                [
                    (f"{rec_type}_empty", f"{rec_type}|"),
                    (f"{rec_type}_many_fields", f"{rec_type}|" + "|".join(["X"] * 100)),
                    (f"{rec_type}_long_field", f"{rec_type}|" + "A" * 5000),
                    (f"{rec_type}_special_chars", f"{rec_type}|<>&'\"\\/"),
                    (f"{rec_type}_unicode", f"{rec_type}|test"),
                ]
            )

        for test_name, payload in fuzz_cases[:iterations]:
            test_count += 1
            try:
                if isinstance(payload, bytes):
                    # Raw byte payload
                    if self.conn:
                        self.conn.sendall(payload)
                        try:
                            self.conn.recv(1, socket.MSG_PEEK)
                        except TimeoutError as e:
                            self.logger.debug(
                                f"self.conn.recv(1, socket.MSG_PEEK): {e}"
                            )  # Expected - no response to fuzz payload
                else:
                    # String payload - send as frame
                    if self._send_enq():
                        header = self.record_builder.build_header(sender_name="FUZZ")
                        self._send_frame(header)
                        self._send_frame(payload)
                        self._send_eot()

            except (BrokenPipeError, ConnectionResetError):
                crash_count += 1
                self.logger.warning(f"Connection lost on test: {test_name}")
                # Reconnect
                if not self.create_conn_obj():
                    break
            except Exception as e:
                error_count += 1
                self.logger.debug(f"Error on {test_name}: {e}")

        self.logger.display(
            f"Fuzzing complete: {test_count} tests, {error_count} errors, {crash_count} crashes"
        )

        self.results["data"]["fuzz_results"] = {
            "tests": test_count,
            "errors": error_count,
            "crashes": crash_count,
        }

        if crash_count > 0:
            self.results["data"].setdefault("security_findings", []).append(
                {
                    "severity": "HIGH",
                    "operation": "Fuzzing",
                    "issue": "Connection Instability",
                    "description": f"Endpoint crashed/disconnected {crash_count} times during fuzzing",
                }
            )

    def _analyze_security(self):
        """Analyze security posture of ASTM endpoint"""
        findings = self.results["data"].setdefault("security_findings", [])
        existing_issues = {f.get("issue") for f in findings}

        # No authentication (always true for ASTM)
        if "No Authentication" not in existing_issues:
            findings.append(
                {
                    "severity": "HIGH",
                    "issue": "No Authentication",
                    "description": "ASTM protocol has no native authentication mechanism",
                    "recommendation": "Implement network-level controls (VPN, firewall, VLANs)",
                }
            )

        # No encryption
        if (
            not getattr(self.args, "tls", False)
            and "Unencrypted Communication" not in existing_issues
        ):
            findings.append(
                {
                    "severity": "HIGH",
                    "issue": "Unencrypted Communication",
                    "description": "ASTM traffic is transmitted in plaintext (PHI exposure risk)",
                    "recommendation": "Use ASTM over TLS or VPN tunnel",
                }
            )
