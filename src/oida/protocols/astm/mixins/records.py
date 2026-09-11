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

        link_ack = self._send_frame(query)

        # Terminator and EOT
        terminator = self.record_builder.build_terminator()
        self._send_frame(terminator)
        self._send_eot()

        if link_ack:
            # A frame-level ACK only confirms data-link receipt. Probe for an
            # application-level reply before claiming the query was honored.
            app_accepted = self._read_application_ack()
            self.results["data"]["query_accepted"] = True
            self.results["data"]["query_app_accepted"] = app_accepted
            if app_accepted:
                self.logger.success("Query record accepted (application reply received)")
                self.results["data"].setdefault("security_findings", []).append(
                    {
                        "operation": "Query",
                        "issue": "Query Access Available",
                        "description": "Endpoint returns query results to an unknown sender "
                        "(application-level reply observed)",
                    }
                )
            else:
                self.logger.display(
                    "Query frame accepted at link level (application acceptance unverified)"
                )
                self.results["data"].setdefault("security_findings", []).append(
                    {
                        "operation": "Query",
                        "issue": "Query Frame Accepted (Link-Level)",
                        "description": "Endpoint accepted the query frame at link level "
                        "(application acceptance unverified - no application-level reply)",
                    }
                )
        else:
            self.logger.warning("Query record rejected")
            self.results["data"]["query_accepted"] = False

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

        link_ack = self._send_frame(patient)

        terminator = self.record_builder.build_terminator()
        self._send_frame(terminator)
        self._send_eot()

        if link_ack:
            # Link-level ACK != application acceptance. Only claim injection is
            # possible if the LIS returns an application-level acknowledgement.
            app_accepted = self._read_application_ack()
            self.results["data"]["patient_accepted"] = True
            self.results["data"]["patient_app_accepted"] = app_accepted
            if app_accepted:
                self.logger.success("Patient record accepted - PATIENT INJECTION POSSIBLE")
                self.results["data"].setdefault("security_findings", []).append(
                    {
                        "operation": "Patient",
                        "issue": "Patient Injection Possible",
                        "description": "LIS application accepted patient record (application-level "
                        "acknowledgement observed) - forged patient demographics can be injected",
                    }
                )
            else:
                self.logger.display(
                    "Patient frame accepted at link level (application acceptance unverified)"
                )
                self.results["data"].setdefault("security_findings", []).append(
                    {
                        "operation": "Patient",
                        "issue": "Patient Frame Accepted (Link-Level)",
                        "description": "Endpoint accepted the patient frame at link level "
                        "(application acceptance unverified - no application-level reply)",
                    }
                )
        else:
            self.logger.warning("Patient record rejected")

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

        link_ack = self._send_frame(order)

        terminator = self.record_builder.build_terminator()
        self._send_frame(terminator)
        self._send_eot()

        if link_ack:
            # Link-level ACK is not application acceptance. Probe for an
            # application-level reply before raising a CRITICAL finding.
            app_accepted = self._read_application_ack()
            self.results["data"]["order_accepted"] = True
            self.results["data"]["order_action"] = action_code
            self.results["data"]["order_app_accepted"] = app_accepted
            if app_accepted:
                if action_code == "C":
                    self.logger.success("Order CANCEL accepted - ORDER CANCELLATION POSSIBLE")
                    issue = "Order Cancellation Possible"
                    desc = "LIS application accepted order cancellation - can disrupt pending tests"
                elif action_code == "X":
                    self.logger.success("Order DELETE accepted - ORDER DELETION POSSIBLE")
                    issue = "Order Deletion Possible"
                    desc = "LIS application accepted order deletion - can remove test orders"
                else:
                    self.logger.success("Order record accepted - ORDER INJECTION POSSIBLE")
                    issue = "Order Injection Possible"
                    desc = "LIS application accepted order record - test orders can be injected"
                self.results["data"].setdefault("security_findings", []).append(
                    {
                        "operation": f"Order ({action_desc})",
                        "issue": issue,
                        "description": desc + " (application-level acknowledgement observed)",
                    }
                )
            else:
                self.logger.display(
                    "Order frame accepted at link level (application acceptance unverified)"
                )
                self.results["data"].setdefault("security_findings", []).append(
                    {
                        "operation": f"Order ({action_desc})",
                        "issue": "Order Frame Accepted (Link-Level)",
                        "description": "Endpoint accepted the order frame at link level "
                        "(application acceptance unverified - no application-level reply)",
                    }
                )
        else:
            self.logger.display("Order record rejected")

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

        link_ack = self._send_frame(result)

        terminator = self.record_builder.build_terminator()
        self._send_frame(terminator)
        self._send_eot()

        if link_ack:
            # Link-level ACK is not application acceptance. Probe for an
            # application-level reply before raising a CRITICAL finding.
            app_accepted = self._read_application_ack()
            self.results["data"]["result_accepted"] = True
            self.results["data"]["result_status"] = result_status
            self.results["data"]["result_value"] = getattr(self.args, "result_value", "") or "100"
            self.results["data"]["result_app_accepted"] = app_accepted
            if app_accepted:
                if result_status == "C":
                    self.logger.success("Result CORRECTION accepted - RESULT MODIFICATION POSSIBLE")
                    issue = "Result Correction Possible"
                    desc = "LIS application accepted corrected result - existing results can be modified"
                elif result_status == "X":
                    self.logger.success("Result DELETION accepted - RESULT DELETION POSSIBLE")
                    issue = "Result Deletion Possible"
                    desc = "LIS application accepted result deletion - lab results can be removed"
                else:
                    self.logger.success("Result record accepted - RESULT INJECTION POSSIBLE")
                    issue = "Result Injection Possible"
                    desc = "LIS application accepted result record - lab results can be falsified"
                self.results["data"].setdefault("security_findings", []).append(
                    {
                        "operation": f"Result ({status_desc})",
                        "issue": issue,
                        "description": desc + " (application-level acknowledgement observed)",
                    }
                )
            else:
                self.logger.display(
                    "Result frame accepted at link level (application acceptance unverified)"
                )
                self.results["data"].setdefault("security_findings", []).append(
                    {
                        "operation": f"Result ({status_desc})",
                        "issue": "Result Frame Accepted (Link-Level)",
                        "description": "Endpoint accepted the result frame at link level "
                        "(application acceptance unverified - no application-level reply)",
                    }
                )
        else:
            self.logger.display("Result record rejected")
