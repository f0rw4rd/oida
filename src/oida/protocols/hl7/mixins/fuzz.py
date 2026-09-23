"""
HL7 Fuzz Mixin

Handles message fuzzing operations:
- Protocol-specific test cases
- Mutation-based fuzzing on all message types
"""


class FuzzMixin:
    """Mixin providing HL7 message fuzzing operations."""

    def _fuzz_messages(self):
        """Fuzz HL7 messages with malformed data"""
        from oida.utils.fuzzer import fuzz

        if not self.require_confirm("--confirm", detail="Fuzzing requires --confirm flag"):
            return
        self.logger.display("Starting HL7 message fuzzing...")
        fuzz_results = []

        # Phase 1: Protocol-specific test cases
        test_cases = [
            ("Empty message", ""),
            ("No MSH", "PID|1||12345^^^MRN||DOE^JOHN"),
            ("Invalid delimiter", "MSH;^~\\&;SENDING;FACILITY"),
            ("Oversized field", "MSH|^~\\&|" + "A" * 10000),
            ("Null bytes", "MSH|^~\\&|\x00\x00\x00"),
            ("SQL injection", "MSH|^~\\&|'; DROP TABLE patients; --"),
            ("XSS payload", "MSH|^~\\&|<script>alert(1)</script>"),
        ]

        for name, payload in test_cases:
            try:
                response = self._send_mllp_message(payload)
                if response:
                    fuzz_results.append(
                        {
                            "test": name,
                            "result": "response_received",
                            "response_len": len(response),
                        }
                    )
                    self.logger.display(f"  {name}: Response received ({len(response)} bytes)")
                else:
                    fuzz_results.append({"test": name, "result": "no_response"})
                    self.logger.display(f"  {name}: No response")
            except Exception as e:
                self.logger.debug("fuzz messages failed: %s", e)
                fuzz_results.append({"test": name, "result": "error", "error": str(e)})
                self.logger.display(f"  {name}: Error - {e}")

        # Phase 2: Mutation fuzzing for ALL message types
        self.logger.display("Running mutation-based fuzzing on all message types...")
        iterations = getattr(self.args, "fuzz_iterations", 10)
        fuzz_segment = getattr(self.args, "fuzz_segment", None)

        # Get message types - reuse shared list
        message_types = self._get_fuzz_message_types()
        total_tests = 0
        total_responses = 0
        total_errors = 0

        for msg_type, trigger, description, risk in message_types:
            self.logger.display(f"  Fuzzing {msg_type}^{trigger} ({description})...")

            # Generate base message using existing method
            base_msg = self._create_test_message(msg_type, trigger)
            if not base_msg:
                self.logger.debug(f"Could not create {msg_type}^{trigger} message")
                continue

            # Optional: segment-specific fuzzing
            if fuzz_segment:
                base_msg = self._inject_fuzz_segment(base_msg, fuzz_segment)

            mutation_results = {
                "type": f"{msg_type}^{trigger}",
                "description": description,
                "risk": risk,
                "tests": 0,
                "responses": 0,
                "errors": 0,
            }

            for payload, fuzz_desc in fuzz(base_msg.encode(), count=iterations):
                try:
                    response = self._send_mllp_message(payload.decode("utf-8", errors="replace"))
                    mutation_results["tests"] += 1
                    if response:
                        mutation_results["responses"] += 1
                except Exception as e:
                    self.logger.debug(f"Fuzz mutation ({fuzz_desc}) error: {e}")
                    mutation_results["errors"] += 1

            fuzz_results.append(mutation_results)
            total_tests += mutation_results["tests"]
            total_responses += mutation_results["responses"]
            total_errors += mutation_results["errors"]
            self.logger.display(
                f"    {mutation_results['tests']} tests, "
                f"{mutation_results['responses']} responses, "
                f"{mutation_results['errors']} errors"
            )

        # Summary
        self.logger.display(
            f"Summary: {len(message_types)} message types fuzzed, "
            f"{total_tests} total tests, {total_responses} responses, {total_errors} errors"
        )

        self.results["data"]["fuzz_results"] = fuzz_results
