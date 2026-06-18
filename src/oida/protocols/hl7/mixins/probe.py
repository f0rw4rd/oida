"""
HL7 Probe Mixin

Handles operation probing:
- Testing which HL7 message types the server accepts
- Displaying probe results with risk categorization
"""

from typing import Dict


class ProbeMixin:
    """Mixin providing HL7 operation probing."""

    def _probe_operations(self):
        """Probe which HL7 message types the server accepts"""
        self.logger.display("Probing supported message types...")

        # Use shared message types list
        MESSAGE_TYPES = self._get_fuzz_message_types()

        results = {
            "supported": [],
            "rejected": [],
            "error": [],
            "timeout": [],
        }

        for msg_type, trigger, description, risk in MESSAGE_TYPES:
            # Create minimal test message
            msg = self._create_test_message(msg_type, trigger)
            if not msg:
                self.logger.debug(f"Could not create {msg_type}^{trigger} message")
                continue

            # Send and check response
            response = self._send_mllp_message(msg)
            ack = self._extract_ack_code(response)

            # Categorize result
            entry = (msg_type, trigger, description, risk)
            if ack in ("AA", "CA"):  # Application Accept / Commit Accept
                results["supported"].append(entry)
            elif ack in ("AR", "CR"):  # Application Reject / Commit Reject
                results["rejected"].append(entry)
            elif ack in ("AE", "CE"):  # Application Error / Commit Error
                results["error"].append(entry)
            else:
                results["timeout"].append(entry)

        # Display results
        self._display_probe_results(results)

        # Store for export
        self.results["data"]["probe_results"] = {
            "supported": [(t, e, d) for t, e, d, _ in results["supported"]],
            "rejected": [(t, e, d) for t, e, d, _ in results["rejected"]],
            "error": [(t, e, d) for t, e, d, _ in results["error"]],
            "timeout": [(t, e, d) for t, e, d, _ in results["timeout"]],
        }

    def _display_probe_results(self, results: Dict):
        """Display probe operation results"""
        # Supported operations
        if results["supported"]:
            self.logger.display("Supported Operations:")
            for msg_type, trigger, desc, risk in results["supported"]:
                if risk == "HIGH":
                    self.logger.success(f"  {msg_type}^{trigger} - {desc} [DANGEROUS]")
                else:
                    self.logger.success(f"  {msg_type}^{trigger} - {desc}")

        # Rejected operations
        if results["rejected"]:
            self.logger.display("Rejected Operations:")
            for msg_type, trigger, desc, _ in results["rejected"]:
                self.logger.fail(f"  {msg_type}^{trigger} - {desc}")

        # Error responses (partially supported)
        if results["error"]:
            self.logger.display("Error Responses (may be supported):")
            for msg_type, trigger, desc, _ in results["error"]:
                self.logger.warning(f"  {msg_type}^{trigger} - {desc}")

        # Timeout (unknown)
        if results["timeout"]:
            self.logger.display("No Response (timeout):")
            for msg_type, trigger, desc, _ in results["timeout"]:
                self.logger.display(f"  {msg_type}^{trigger} - {desc}")

        # Summary counts
        supported_count = len(results["supported"])
        rejected_count = len(results["rejected"])
        total_probed = (
            supported_count + rejected_count + len(results["error"]) + len(results["timeout"])
        )
        dangerous_count = sum(1 for _, _, _, r in results["supported"] if r == "HIGH")
        self.logger.display(
            f"Summary: {supported_count}/{total_probed} accepted"
            + (f" ({dangerous_count} dangerous)" if dangerous_count else "")
        )

        # Security findings for dangerous operations
        dangerous_triggers = {"A40", "A03", "O01", "O11"}  # Merge, Discharge, Orders, Pharmacy
        for msg_type, trigger, desc, risk in results["supported"]:
            if trigger in dangerous_triggers or risk == "HIGH":
                self.results["data"].setdefault("security_findings", []).append(
                    {
                        "severity": "HIGH" if risk == "HIGH" else "MEDIUM",
                        "operation": f"{msg_type}^{trigger}",
                        "issue": f"Dangerous Operation Accepted ({desc})",
                        "description": f"Server accepts {desc} messages from unknown sender",
                        "recommendation": "Implement sender validation and message filtering",
                    }
                )
