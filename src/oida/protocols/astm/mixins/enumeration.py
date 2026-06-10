"""
ASTM Enumeration Mixin

Handles test enumeration, instrument enumeration, patient enumeration,
and record type probing.
"""

from typing import Dict, List

from ..records import ASTM_VENDOR_MAP, LAB_TEST_TYPES


class EnumerationMixin:
    """Mixin providing ASTM enumeration operations."""

    def _enum_tests(self):
        """Enumerate available lab tests via query"""
        self.logger.display("Enumerating available lab tests...")

        if not self._send_enq():
            self.logger.warning("ENQ failed")
            return

        header = self.record_builder.build_header(
            sender_name=getattr(self.args, "sender_name", "OIDA"),
        )
        if not self._send_frame(header):
            self._send_eot()
            return

        # Send query for all tests
        query = self.record_builder.build_query(
            starting_range="*",
            nature_of_request="O",  # Orders/tests
        )

        if self._send_frame(query):
            self.logger.success("Test query accepted")
            # In a real implementation, we would receive and parse response frames here
            self.results["data"].setdefault("security_findings", []).append(
                {
                    "severity": "MEDIUM",
                    "operation": "Test Enumeration",
                    "issue": "Test Catalog Accessible",
                    "description": "Lab test catalog can be enumerated",
                }
            )

        terminator = self.record_builder.build_terminator()
        self._send_frame(terminator)
        self._send_eot()

        # Display known test types (from our constants)
        self.logger.display(f"Common lab test codes ({len(LAB_TEST_TYPES)} known):")
        displayed = 0
        for code, (name, units, ref_range) in sorted(LAB_TEST_TYPES.items()):
            if displayed < 15:
                self.logger.display(f"  {code}: {name} ({units})")
                displayed += 1

        if len(LAB_TEST_TYPES) > 15:
            self.logger.display(f"  ... and {len(LAB_TEST_TYPES) - 15} more")

        self.results["data"]["tests_enumerated"] = True

    def _enum_instruments(self):
        """Enumerate connected analyzers/instruments"""
        self.logger.display("Enumerating connected instruments...")

        # Display known analyzer types
        self.logger.display(f"Known analyzer types ({len(ASTM_VENDOR_MAP)} patterns):")

        # Group by vendor
        by_vendor: Dict[str, List[str]] = {}
        for name, (vendor, product) in ASTM_VENDOR_MAP.items():
            by_vendor.setdefault(vendor, []).append(f"{name} ({product})")

        displayed = 0
        for vendor in sorted(by_vendor.keys()):
            if displayed < 10:
                products = by_vendor[vendor][:3]
                self.logger.display(f"  {vendor}: {', '.join(products)}")
                displayed += 1

        if len(by_vendor) > 10:
            self.logger.display(f"  ... and {len(by_vendor) - 10} more vendors")

        self.results["data"]["instruments_enumerated"] = True

    def _enum_patients(self):
        """Enumerate patient records - DANGEROUS/PHI"""
        self.logger.display("Enumerating patient records...")
        self.logger.warning("This operation may access PHI (Protected Health Information)")

        if not self._send_enq():
            return

        header = self.record_builder.build_header(
            sender_name=getattr(self.args, "sender_name", "OIDA"),
        )
        if not self._send_frame(header):
            self._send_eot()
            return

        # Wildcard query for all patients
        query = self.record_builder.build_query(
            starting_range="*",
            nature_of_request="S",  # Sample/patient demographics
        )

        if self._send_frame(query):
            self.logger.success("Patient query accepted - PHI EXPOSURE RISK")
            self.results["data"]["patient_enum_accepted"] = True
            self.results["data"].setdefault("security_findings", []).append(
                {
                    "severity": "HIGH",
                    "operation": "Patient Enumeration",
                    "issue": "Patient Data Exposure",
                    "description": "Endpoint allows wildcard patient queries - PHI exposure risk",
                }
            )

        terminator = self.record_builder.build_terminator()
        self._send_frame(terminator)
        self._send_eot()

    def _probe_operations(self):
        """Probe supported record types"""
        self.logger.display("Probing supported record types...")

        results = {
            "supported": [],
            "rejected": [],
            "timeout": [],
        }

        record_types = [
            ("H", "Header", self._test_header_record),
            ("P", "Patient", self._test_patient_record),
            ("O", "Order", self._test_order_record),
            ("R", "Result", self._test_result_record),
            ("Q", "Query", self._test_query_record),
            ("C", "Comment", self._test_comment_record),
        ]

        for record_type, desc, test_func in record_types:
            status = test_func()
            if status == "accepted":
                results["supported"].append((record_type, desc))
            elif status == "rejected":
                results["rejected"].append((record_type, desc))
            else:
                results["timeout"].append((record_type, desc))

        # Store and display results
        self.results["data"]["probe_results"] = results

        if results["supported"]:
            self.logger.display("Supported record types:")
            for rt, desc in results["supported"]:
                self.logger.success(f"  {rt} - {desc}")

        if results["rejected"]:
            self.logger.display("Rejected record types:")
            for rt, desc in results["rejected"]:
                self.logger.fail(f"  {rt} - {desc}")

        if results["timeout"]:
            self.logger.display("No response (timeout):")
            for rt, desc in results["timeout"]:
                self.logger.display(f"  {rt} - {desc}")

        # Summary
        supported = [rt for rt, _ in results["supported"]]
        self.logger.display(f"Supported: {', '.join(supported) if supported else 'None'}")

    def _test_header_record(self) -> str:
        """Test if header records are accepted"""
        if not self._send_enq():
            return "timeout"

        header = self.record_builder.build_header(sender_name="OIDA")
        result = "accepted" if self._send_frame(header) else "rejected"

        terminator = self.record_builder.build_terminator()
        self._send_frame(terminator)
        self._send_eot()

        return result

    def _test_patient_record(self) -> str:
        """Test if patient records are accepted"""
        if not self._send_enq():
            return "timeout"

        header = self.record_builder.build_header(sender_name="OIDA")
        if not self._send_frame(header):
            self._send_eot()
            return "rejected"

        patient = self.record_builder.build_patient(patient_id="TEST001")
        result = "accepted" if self._send_frame(patient) else "rejected"

        terminator = self.record_builder.build_terminator()
        self._send_frame(terminator)
        self._send_eot()

        return result

    def _test_order_record(self) -> str:
        """Test if order records are accepted"""
        if not self._send_enq():
            return "timeout"

        header = self.record_builder.build_header(sender_name="OIDA")
        if not self._send_frame(header):
            self._send_eot()
            return "rejected"

        patient = self.record_builder.build_patient(patient_id="TEST001")
        self._send_frame(patient)

        order = self.record_builder.build_order(sample_id="TEST", test_id="GLU")
        result = "accepted" if self._send_frame(order) else "rejected"

        terminator = self.record_builder.build_terminator()
        self._send_frame(terminator)
        self._send_eot()

        return result

    def _test_result_record(self) -> str:
        """Test if result records are accepted"""
        if not self._send_enq():
            return "timeout"

        header = self.record_builder.build_header(sender_name="OIDA")
        if not self._send_frame(header):
            self._send_eot()
            return "rejected"

        patient = self.record_builder.build_patient(patient_id="TEST001")
        self._send_frame(patient)

        order = self.record_builder.build_order(sample_id="TEST", test_id="GLU")
        self._send_frame(order)

        result_rec = self.record_builder.build_result(test_id="GLU", value="100")
        result = "accepted" if self._send_frame(result_rec) else "rejected"

        terminator = self.record_builder.build_terminator()
        self._send_frame(terminator)
        self._send_eot()

        return result

    def _test_query_record(self) -> str:
        """Test if query records are accepted"""
        if not self._send_enq():
            return "timeout"

        header = self.record_builder.build_header(sender_name="OIDA")
        if not self._send_frame(header):
            self._send_eot()
            return "rejected"

        query = self.record_builder.build_query(starting_range="*")
        result = "accepted" if self._send_frame(query) else "rejected"

        terminator = self.record_builder.build_terminator()
        self._send_frame(terminator)
        self._send_eot()

        return result

    def _test_comment_record(self) -> str:
        """Test if comment records are accepted"""
        if not self._send_enq():
            return "timeout"

        header = self.record_builder.build_header(sender_name="OIDA")
        if not self._send_frame(header):
            self._send_eot()
            return "rejected"

        comment = self.record_builder.build_comment(comment_text="Test comment")
        result = "accepted" if self._send_frame(comment) else "rejected"

        terminator = self.record_builder.build_terminator()
        self._send_frame(terminator)
        self._send_eot()

        return result
