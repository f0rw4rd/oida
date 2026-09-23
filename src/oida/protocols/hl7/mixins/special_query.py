"""
HL7 Special Query Mixin

Handles QBP special queries:
- QBP^Q40 (WhoAmI) - server capability identification
- QBP^Q13 (Tabular Query) - tabular data retrieval
- QBP^Z34 (Immunization History)
- QBP^Z44 (Immunization History + Forecast)
"""

import time
from typing import Optional

from hl7apy.core import Message, Segment
from hl7apy.parser import parse_message

from oida.protocols.hl7.segments import HL7SegmentParser
from oida.protocols.hl7.mixins._helpers import build_rcp, populate_msh


class SpecialQueryMixin:
    """Mixin providing HL7 special query operations."""

    def _send_qbp_q40_message(self):
        """Send QBP^Q40 (WhoAmI) query to identify server capabilities"""
        self.logger.display("Sending QBP^Q40 (WhoAmI) query...")

        msg = self._create_qbp_message("Q40", "WhoAmI")
        if msg:
            response = self._send_query_message(msg)
            if response:
                self.logger.success("Received WhoAmI response")
                self._parse_response(response)
                self._extract_whoami_results(response)
            else:
                self.logger.warning("No response to QBP^Q40 message")

    def _send_qbp_q13_message(self):
        """Send QBP^Q13 tabular query"""
        self.logger.display("Sending QBP^Q13 (Tabular Query)...")

        msg = self._create_qbp_message("Q13", "TabularPatientList")
        if msg:
            response = self._send_query_message(msg)
            if response:
                self.logger.success("Received RTB (Tabular Response)")
                self._parse_response(response)
                self._extract_rtb_results(response)
            else:
                self.logger.warning("No response to QBP^Q13 message")

    def _send_qbp_z34_message(self):
        """Send QBP^Z34 immunization history query"""
        self.logger.display("Sending QBP^Z34 (Immunization History Query)...")

        patient_id = getattr(self.args, "patient_id", None)
        if not patient_id:
            self.logger.fail("QBP^Z34 requires --patient-id")
            return

        msg = self._create_qbp_immunization_message("Z34", patient_id)
        if msg:
            response = self._send_query_message(msg)
            if response:
                self.logger.success("Received RSP^Z32 (Immunization History Response)")
                self._parse_response(response)
                self._extract_immunization_results(response)
            else:
                self.logger.warning("No response to QBP^Z34 message")

    def _send_qbp_z44_message(self):
        """Send QBP^Z44 immunization history + forecast query"""
        self.logger.display("Sending QBP^Z44 (Immunization History + Forecast Query)...")

        patient_id = getattr(self.args, "patient_id", None)
        if not patient_id:
            self.logger.fail("QBP^Z44 requires --patient-id")
            return

        msg = self._create_qbp_immunization_message("Z44", patient_id)
        if msg:
            response = self._send_query_message(msg)
            if response:
                self.logger.success("Received RSP^Z42 (Immunization + Forecast Response)")
                self._parse_response(response)
                self._extract_immunization_results(response)
            else:
                self.logger.warning("No response to QBP^Z44 message")

    def _create_qbp_message(self, query_tag: str, query_name: str) -> Optional[str]:
        """Create generic QBP (Query By Parameter) message"""
        try:
            version = self._get_version()
            msg = Message("QBP_Q13", version=version)

            populate_msh(
                msg,
                self.args,
                version=version,
                msg_type=f"QBP^{query_tag}^QBP_Q13",
                control_prefix="QBP",
            )

            # QPD segment (Query Parameter Definition)
            qpd = Segment("QPD", version=version)
            qpd.qpd_1 = f"{query_tag}^{query_name}^HL70471"
            qpd.qpd_2 = f"Q{int(time.time())}"  # Query tag
            # QPD-3: Query parameters (patient ID if provided)
            patient_id = getattr(self.args, "patient_id", None)
            if patient_id:
                qpd.qpd_3 = f"{patient_id}^^^HOSPITAL^MR"
            msg.add(qpd)

            rcp = build_rcp(version)
            msg.add(rcp)

            return msg.to_er7()

        except Exception as e:
            self.logger.debug(f"Failed to create QBP^{query_tag} message: {e}")
            return self._create_test_message("QBP", query_tag)

    def _create_qbp_immunization_message(self, query_tag: str, patient_id: str) -> Optional[str]:
        """Create QBP immunization query message (Z34/Z44)"""
        try:
            version = self._get_version()
            msg = Message("QBP_Q13", version=version)

            populate_msh(
                msg,
                self.args,
                version=version,
                msg_type=f"QBP^{query_tag}^QBP_Q11",
                control_prefix="IMM",
                receiving_app="IIS",  # Immunization Information System
            )

            # QPD segment for immunization query
            qpd = Segment("QPD", version=version)
            if query_tag == "Z34":
                qpd.qpd_1 = "Z34^Request Immunization History^CDCPHINVS"
            else:
                qpd.qpd_1 = "Z44^Request Evaluated History and Forecast^CDCPHINVS"
            qpd.qpd_2 = f"IMM{int(time.time())}"
            qpd.qpd_3 = f"{patient_id}^^^HOSPITAL^MR"
            msg.add(qpd)

            rcp = build_rcp(version)
            msg.add(rcp)

            return msg.to_er7()

        except Exception as e:
            self.logger.debug(f"Failed to create QBP^{query_tag} message: {e}")
            return None

    def _extract_whoami_results(self, response: bytes):
        """Extract server capability info from WhoAmI response"""
        try:
            msg_str = response.decode("utf-8", errors="ignore")
            msg = parse_message(msg_str)

            whoami_info = {}

            # Extract MSH info
            if hasattr(msg, "msh"):
                msh = msg.msh
                whoami_info["server_app"] = self._get_field_value(msh, "msh_3")
                whoami_info["server_facility"] = self._get_field_value(msh, "msh_4")
                whoami_info["version"] = self._get_field_value(msh, "msh_12")

            # Display results
            if whoami_info:
                self.logger.display("Server Identification (WhoAmI):")
                for key, value in whoami_info.items():
                    if value:
                        self.logger.display(f"  {key}: {value}")

            self.results["data"]["whoami_results"] = whoami_info

        except Exception as e:
            self.logger.debug(f"Failed to extract WhoAmI results: {e}")

    def _extract_rtb_results(self, response: bytes):
        """Extract tabular data from RTB response"""
        try:
            segments = HL7SegmentParser.split_message(response)
            rows = []
            columns = []

            for segment in segments:
                if segment.startswith("RDF|"):
                    # Row Definition segment - defines columns
                    fields = segment.split("|")
                    if len(fields) > 2:
                        col_defs = fields[2].split("~")
                        columns = [c.split("^")[0] for c in col_defs if c]

                elif segment.startswith("RDT|"):
                    # Row Data segment - actual data
                    fields = segment.split("|")
                    if len(fields) > 1:
                        row_data = fields[1].split("~")
                        rows.append(row_data)

            if rows:
                self.logger.display(f"Tabular Results: {len(rows)} row(s)")
                if columns:
                    self.logger.display(f"  Columns: {', '.join(columns)}")
                for i, row in enumerate(rows[:10]):
                    self.logger.display(f"  Row {i + 1}: {' | '.join(row)}")
                if len(rows) > 10:
                    self.logger.display(f"  ... and {len(rows) - 10} more rows")

            self.results["data"]["tabular_results"] = {
                "columns": columns,
                "rows": rows,
                "count": len(rows),
            }

        except Exception as e:
            self.logger.debug(f"Failed to extract RTB results: {e}")

    def _extract_immunization_results(self, response: bytes):
        """Extract immunization data from RSP response"""
        try:
            parsed = HL7SegmentParser.parse_message(response)
            medications = parsed.get("medications", [])

            # RXA segments contain immunization administration records
            if medications:
                column_defs = [
                    ("PatientID", "Patient"),
                    ("DrugCode", "Vaccine Code"),
                    ("DrugName", "Vaccine Name"),
                    ("AdminDate", "Admin Date"),
                    ("Dose", "Dose"),
                    ("LotNumber", "Lot#"),
                    ("Manufacturer", "Manufacturer"),
                    ("Status", "Status"),
                ]
                self._display_results_table(
                    items=medications,
                    column_defs=column_defs,
                    result_key="immunization_results",
                    result_label="immunization record(s)",
                    security_finding={
                        "operation": "QBP^Z34/Z44",
                        "issue": "Immunization Records Accessible",
                        "description": f"Query returned {len(medications)} immunization records",
                    },
                )
            else:
                self.logger.display("  No immunization records found in response")

        except Exception as e:
            self.logger.debug(f"Failed to extract immunization results: {e}")
