"""
HL7 Query Mixin

Handles QRY/QBP query message construction and sending:
- QRY^Q01 (Patient Query)
- QRY^R02 (Observation Results Query)
- QBP^Q31 (Pharmacy Dispense History Query)
- OSQ^Q06 (Order Status Query)
"""

import time
from typing import Optional

from hl7apy.core import Message, Segment

from oida.protocols.hl7.mixins._helpers import ack_accepted, build_qrd, build_rcp, populate_msh


class QueryMixin:
    """Mixin providing HL7 query message operations."""

    def _send_qry_message(self):
        """Send QRY^Q01 (Query) message to retrieve patient data"""
        enum_patients = getattr(self.args, "enum_patients", False)
        if enum_patients:
            self.logger.display(
                "Sending QRY^Q01 (Query) with WILDCARD to enumerate all patients..."
            )
        else:
            self.logger.display("Sending QRY^Q01 (Query) message...")

        msg = self._create_qry_message()
        if msg:
            response = self._send_query_message(msg)
            if response:
                self.logger.success("Received QRY response")
                self._parse_response(response)
                self._extract_detailed_response(response, "QRY^Q01")

                # Try to extract patient data from response
                self._extract_query_results(response)

                ack = self._extract_ack_code(response)
                if enum_patients and ack_accepted(ack):
                    self.results["data"].setdefault("security_findings", []).append(
                        {
                            "operation": "QRY (wildcard)",
                            "issue": "Wildcard Query Accepted",
                            "description": "Server allows wildcard patient enumeration",
                        }
                    )
            else:
                self.logger.warning("No response to QRY message")

    def _send_qry_obs_message(self):
        """Send QRY^R02 (Observation Results Query) to retrieve lab results, vitals"""
        self.logger.display("Sending QRY^R02 (Observation Results Query)...")

        msg = self._create_qry_r02_message()
        if msg:
            response = self._send_query_message(msg)
            if response:
                self.logger.success("Received ORF response")
                self._parse_response(response)
                self._extract_detailed_response(response, "ORF^R04")
                self._extract_observation_results(response)
            else:
                self.logger.warning("No response to QRY^R02 message")

    def _send_qry_rx_message(self):
        """Send QBP^Q31 (Pharmacy Dispense History Query) to retrieve medication history"""
        self.logger.display("Sending QBP^Q31 (Pharmacy Dispense History Query)...")

        msg = self._create_qbp_q31_message()
        if msg:
            response = self._send_query_message(msg)
            if response:
                self.logger.success("Received RSP^K31 response")
                self._parse_response(response)
                self._extract_detailed_response(response, "RSP^K31")
                self._extract_pharmacy_results(response)
            else:
                self.logger.warning("No response to QBP^Q31 message")

    def _send_qry_orders_message(self):
        """Send OSQ^Q06 (Order Status Query) to check order status"""
        self.logger.display("Sending OSQ^Q06 (Order Status Query)...")

        msg = self._create_osq_q06_message()
        if msg:
            response = self._send_query_message(msg)
            if response:
                self.logger.success("Received OSR response")
                self._parse_response(response)
                self._extract_detailed_response(response, "OSR^Q06")
                self._extract_order_status(response)
            else:
                self.logger.warning("No response to OSQ^Q06 message")

    def _create_qry_message(self) -> Optional[str]:
        """Create QRY^Q01 query message with optional wildcard support"""
        try:
            version = self._get_version()
            msg = Message("QRY_Q01", version=version)

            populate_msh(
                msg,
                self.args,
                version=version,
                msg_type="QRY^Q01",
                control_prefix="QRY",
            )

            # What to query - use wildcard if --enum-patients
            enum_patients = getattr(self.args, "enum_patients", False)
            if enum_patients:
                patient_id = "*"  # Wildcard to enumerate all patients
            else:
                patient_id = getattr(self.args, "patient_id", None) or "*"

            qrd = build_qrd(version, query_id_prefix="Q", who_subject=patient_id)
            msg.add(qrd)

            return msg.to_er7()

        except Exception as e:
            self.logger.debug(f"Failed to create QRY^Q01 message: {e}")
            return self._create_test_message("QRY", "Q01")

    def _create_qry_r02_message(self) -> Optional[str]:
        """Create QRY^R02 message to query observation results (lab results, vitals)"""
        try:
            version = self._get_version()
            msg = Message("QRY_R02", version=version)

            populate_msh(
                msg,
                self.args,
                version=version,
                msg_type="QRY^R02",
                control_prefix="OBS",
                receiving_app="LAB",
            )

            qrd = build_qrd(
                version,
                query_id_prefix="OBS",
                result_format="RD",
                who_subject=getattr(self.args, "patient_id", None) or "*",
                what_subject="OTH",
                what_dept="T",
            )
            msg.add(qrd)

            # QRF segment (Query Filter) - optional but useful for filtering
            qrf = Segment("QRF", version=version)
            qrf.qrf_1 = "OBX"  # Where subject filter - observation segments
            obx_id = getattr(self.args, "obx_id", None)
            if obx_id:
                qrf.qrf_2 = obx_id

            msg.add(qrf)

            return msg.to_er7()

        except Exception as e:
            self.logger.debug(f"Failed to create QRY^R02 message: {e}")
            return self._create_test_message("QRY", "R02")

    def _create_qbp_q31_message(self) -> Optional[str]:
        """Create QBP^Q31 message to query pharmacy dispense history"""
        try:
            version = self._get_version()
            msg = Message("QBP_Q11", version=version)

            populate_msh(
                msg,
                self.args,
                version=version,
                msg_type="QBP^Q31^QBP_Q11",
                control_prefix="RX",
                receiving_app="PHARMACY",
            )

            # QPD segment (Query Parameter Definition)
            qpd = Segment("QPD", version=version)
            qpd.qpd_1 = "Q31^Dispense History^HL70471"
            qpd.qpd_2 = f"QRX{int(time.time())}"
            qpd.qpd_3 = getattr(self.args, "patient_id", None) or "*"
            msg.add(qpd)

            msg.add(build_rcp(version))

            return msg.to_er7()

        except Exception as e:
            self.logger.debug(f"Failed to create QBP^Q31 message: {e}")
            return self._create_legacy_pharmacy_query()

    def _create_legacy_pharmacy_query(self) -> Optional[str]:
        """Create legacy QRY^Q28 for pharmacy dispense info (older HL7 systems)"""
        try:
            version = self._get_version()
            msg = Message("QRY_Q01", version=version)

            populate_msh(
                msg,
                self.args,
                version=version,
                msg_type="QRY^Q28",
                control_prefix="RXL",
                receiving_app="PHARMACY",
            )

            qrd = build_qrd(
                version,
                query_id_prefix="RXL",
                result_format="RD",
                who_subject=getattr(self.args, "patient_id", None) or "*",
                what_subject="RXD",
            )
            msg.add(qrd)

            return msg.to_er7()

        except Exception as e:
            self.logger.debug(f"Failed to create legacy pharmacy query: {e}")
            return None

    def _create_osq_q06_message(self) -> Optional[str]:
        """Create OSQ^Q06 message to query order status"""
        try:
            version = self._get_version()
            msg = Message("OSQ_Q06", version=version)

            populate_msh(
                msg,
                self.args,
                version=version,
                msg_type="OSQ^Q06",
                control_prefix="ORD",
                receiving_app="ORDER_ENTRY",
            )

            patient_id = getattr(self.args, "patient_id", None)
            order_id = getattr(self.args, "order_id", None)

            qrd = build_qrd(
                version,
                query_id_prefix="ORD",
                result_format="RD",
                who_subject=order_id or patient_id or "*",
                what_subject="ORD",
            )
            msg.add(qrd)

            # QRF segment (Query Filter)
            qrf = Segment("QRF", version=version)
            qrf.qrf_1 = "ORC"
            msg.add(qrf)

            return msg.to_er7()

        except Exception as e:
            self.logger.debug(f"Failed to create OSQ^Q06 message: {e}")
            return self._create_test_message("OSQ", "Q06")
