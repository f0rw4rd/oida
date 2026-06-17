"""
HL7 Message Mixin

Handles creation and sending of core HL7 messages:
- ADT (Admission/Discharge/Transfer) messages
- ORU (Observation Result) messages
- ORM (Order) messages
- SIU (Scheduling) messages
- MDM (Document) messages
- Custom message types
"""

import time
from datetime import datetime
from typing import Optional

from hl7apy.core import Message

from ._helpers import populate_msh


class MessageMixin:
    """Mixin providing HL7 message creation and sending operations."""

    def _send_adt_message(self):
        """Send ADT (Admission/Discharge/Transfer) message with configurable trigger"""
        trigger = getattr(self.args, "adt_trigger", "A01")

        # All ADT messages are write operations and require --confirm
        if not getattr(self.args, "confirm", False):
            self.logger.fail(
                f"ADT^{trigger} is a write operation that modifies patient data. "
                "Use --confirm to proceed."
            )
            return

        # Trigger event descriptions
        trigger_desc = {
            "A01": "Admit",
            "A02": "Transfer",
            "A03": "Discharge",
            "A04": "Register",
            "A05": "Pre-Admit",
            "A08": "Update Patient Info",
            "A11": "Cancel Admit",
            "A12": "Cancel Transfer",
            "A13": "Cancel Discharge",
            "A28": "Add Person Info",
            "A31": "Update Person Info",
            "A40": "Merge Patient",
        }

        desc = trigger_desc.get(trigger, trigger)

        # A40 (Merge) requires MRG segment
        if trigger == "A40":
            msg = self._create_merge_message()
        else:
            msg = self._create_message_with_segments("ADT", trigger)

        if not msg:
            self.logger.fail("ADT requires patient data. Use --patient-id or --patient-name")
            return

        self.logger.display(f"Sending ADT^{trigger} ({desc}) message...")
        response = self._send_mllp_message(msg)
        if response:
            self.logger.success(f"Received ADT^{trigger} response")
            self._parse_response(response)
            self._extract_detailed_response(response, f"ADT^{trigger}")

            # Security finding for dangerous operations
            ack = self.results["data"].get("ack_code", "")
            if ack == "AA" and trigger in ["A03", "A40"]:
                self.results["data"].setdefault("security_findings", []).append(
                    {
                        "operation": f"ADT^{trigger}",
                        "issue": f"Dangerous ADT Operation Accepted ({desc})",
                        "description": f"Server accepted {desc} from unknown source",
                    }
                )
        else:
            self.logger.warning(f"No response to ADT^{trigger} message")

    def _send_oru_message(self):
        """Send ORU (Observation Result) test message"""
        # ORU is a write operation - requires --confirm
        if not getattr(self.args, "confirm", False):
            self.logger.fail(
                "ORU^R01 (Observation Result) is a write operation. Use --confirm to proceed."
            )
            return

        self.logger.display("Sending ORU^R01 (Observation Result) message...")

        msg = self._create_test_message("ORU", "R01")
        if msg:
            response = self._send_mllp_message(msg)
            if response:
                self.logger.success("Received ORU response")
                self._parse_response(response)
            else:
                self.logger.warning("No response to ORU message")

    def _send_custom_message(self, msg_type: str):
        """Send custom message type (e.g., 'ORM^O01')"""
        # Custom messages are write operations - require --confirm
        if not getattr(self.args, "confirm", False):
            self.logger.fail(f"{msg_type} is a write operation. Use --confirm to proceed.")
            return

        self.logger.display(f"Sending {msg_type} message...")

        parts = msg_type.split("^")
        if len(parts) == 2:
            msg = self._create_test_message(parts[0], parts[1])
            if msg:
                response = self._send_mllp_message(msg)
                if response:
                    self.logger.success(f"Received {msg_type} response")
                    self._parse_response(response)
                    self._extract_detailed_response(response, msg_type)
                else:
                    self.logger.warning(f"No response to {msg_type} message")
        else:
            self.logger.fail(f"Invalid message type format: {msg_type} (expected TYPE^EVENT)")

    def _send_orm_message(self):
        """Send ORM^O01 (Order) test message with patient/order segments"""
        # ORM is a write operation - requires --confirm
        if not getattr(self.args, "confirm", False):
            self.logger.fail("ORM^O01 (Order) is a write operation. Use --confirm to proceed.")
            return

        msg = self._create_message_with_segments("ORM", "O01")
        if not msg:
            self.logger.fail("ORM requires patient data. Use --patient-id or --patient-name")
            return

        self.logger.display("Sending ORM^O01 (Order) message...")
        response = self._send_mllp_message(msg)
        if response:
            self.logger.success("Received ORM response")
            self._parse_response(response)
            self._extract_detailed_response(response, "ORM^O01")

            # Security check - order accepted
            ack = self.results["data"].get("ack_code", "")
            if ack == "AA":
                self.results["data"].setdefault("security_findings", []).append(
                    {
                        "operation": "ORM",
                        "issue": "Unvalidated Order Accepted",
                        "description": "Server accepted order from unknown source",
                    }
                )
        else:
            self.logger.warning("No response to ORM message")

    def _send_siu_message(self):
        """Send SIU^S12 (Scheduling) test message"""
        # SIU is a write operation - requires --confirm
        if not getattr(self.args, "confirm", False):
            self.logger.fail("SIU^S12 (Scheduling) is a write operation. Use --confirm to proceed.")
            return

        msg = self._create_message_with_segments("SIU", "S12")
        if not msg:
            self.logger.fail("SIU requires patient data. Use --patient-id or --patient-name")
            return

        self.logger.display("Sending SIU^S12 (Scheduling) message...")
        response = self._send_mllp_message(msg)
        if response:
            self.logger.success("Received SIU response")
            self._parse_response(response)
            self._extract_detailed_response(response, "SIU^S12")
        else:
            self.logger.warning("No response to SIU message")

    def _send_mdm_message(self):
        """Send MDM^T02 (Document Notification) test message"""
        # MDM is a write operation - requires --confirm
        if not getattr(self.args, "confirm", False):
            self.logger.fail("MDM^T02 (Document) is a write operation. Use --confirm to proceed.")
            return

        self.logger.display("Sending MDM^T02 (Document) message...")

        msg = self._create_message_with_segments("MDM", "T02")
        if msg:
            response = self._send_mllp_message(msg)
            if response:
                self.logger.success("Received MDM response")
                self._parse_response(response)
                self._extract_detailed_response(response, "MDM^T02")
            else:
                self.logger.warning("No response to MDM message")

    def _create_message_with_segments(self, msg_type: str, trigger_event: str) -> Optional[str]:
        """Create HL7 message with PID, PV1, OBR, ORC segments based on CLI args"""
        try:
            version = self._get_version()
            msg = Message(f"{msg_type}_{trigger_event}", version=version)

            populate_msh(
                msg,
                self.args,
                version=version,
                msg_type=f"{msg_type}^{trigger_event}",
                control_prefix="MSG",
            )

            # Add PID segment - REQUIRED for ADT/ORM/SIU/ORU
            patient_id = getattr(self.args, "patient_id", None) or getattr(self.args, "mrn", None)
            patient_name = getattr(self.args, "patient_name", None)
            needs_pid = msg_type in ["ADT", "ORM", "SIU", "ORU"]

            if needs_pid and not patient_id and not patient_name:
                return None  # Caller must check and show error

            if patient_id or patient_name:
                pid = self.segment_builder.build_pid(
                    patient_id=patient_id,
                    patient_name=patient_name,
                    dob=getattr(self.args, "patient_dob", ""),
                    sex=getattr(self.args, "patient_sex", ""),
                    address=getattr(self.args, "patient_address", ""),
                    phone=getattr(self.args, "patient_phone", ""),
                    ssn=getattr(self.args, "ssn", "") or "",
                )
                if pid:
                    msg.add(pid)

            # Add PV1 segment if visit data provided
            visit_number = getattr(self.args, "visit_number", None)
            patient_class = getattr(self.args, "patient_class", None)
            location = getattr(self.args, "location", None)
            if visit_number or patient_class or location:
                pv1 = self.segment_builder.build_pv1(
                    patient_class=patient_class or "O",
                    visit_number=visit_number or "",
                    admit_date=getattr(self.args, "admit_date", ""),
                    location=location or "",
                )
                if pv1:
                    msg.add(pv1)

            # Add ORC/OBR for order messages
            if msg_type in ["ORM", "ORU"]:
                order_id = getattr(self.args, "order_id", None)
                order_code = getattr(self.args, "order_code", None)
                if order_id or order_code:
                    orc = self.segment_builder.build_orc(
                        order_control="NW",
                        placer_order=order_id or f"ORD{int(time.time())}",
                    )
                    if orc:
                        msg.add(orc)

                    obr = self.segment_builder.build_obr(
                        order_id=order_id or f"ORD{int(time.time())}",
                        service_id=order_code or "CBC^Complete Blood Count",
                        priority=getattr(self.args, "order_priority", "R"),
                    )
                    if obr:
                        msg.add(obr)

            # Add OBX for observation messages
            if msg_type in ["ORU", "MDM"]:
                obx_value = getattr(self.args, "obx_value", None)
                obx_id = getattr(self.args, "obx_id", None)
                if obx_value or obx_id:
                    obx = self.segment_builder.build_obx(
                        value_type=getattr(self.args, "obx_type", "NM"),
                        observation_id=obx_id or "12345-6",
                        observation_value=obx_value or "100",
                        units=getattr(self.args, "obx_units", "mg/dL"),
                    )
                    if obx:
                        msg.add(obx)

            # Add TXA for document messages
            if msg_type == "MDM":
                txa = self.segment_builder.build_txa(
                    document_type="HP",
                    unique_document_number=f"DOC{int(time.time())}",
                )
                if txa:
                    msg.add(txa)

            # Add SCH for scheduling messages
            if msg_type == "SIU":
                sch = self.segment_builder.build_sch(
                    placer_appointment_id=f"APT{int(time.time())}",
                    start_datetime=datetime.now().strftime("%Y%m%d%H%M%S"),
                )
                if sch:
                    msg.add(sch)

            # Add DG1 (Diagnosis) segment if diagnosis data provided
            dx_code = getattr(self.args, "dx_code", None)
            dx_description = getattr(self.args, "dx_description", None)
            if dx_code or dx_description:
                dg1 = self.segment_builder.build_dg1(
                    diagnosis_code=dx_code or "",
                    diagnosis_description=dx_description or "",
                    diagnosis_type=getattr(self.args, "dx_type", "A"),
                    diagnosis_priority=getattr(self.args, "dx_priority", "1"),
                    diagnosing_clinician=getattr(self.args, "dx_clinician", ""),
                )
                if dg1:
                    msg.add(dg1)

            # Add PR1 (Procedure) segment if procedure data provided
            pr_code = getattr(self.args, "pr_code", None)
            pr_description = getattr(self.args, "pr_description", None)
            if pr_code or pr_description:
                pr1 = self.segment_builder.build_pr1(
                    procedure_code=pr_code or "",
                    procedure_description=pr_description or "",
                    procedure_type=getattr(self.args, "pr_type", ""),
                    procedure_practitioner=getattr(self.args, "pr_practitioner", ""),
                )
                if pr1:
                    msg.add(pr1)

            return msg.to_er7()

        except Exception as e:
            self.logger.debug(f"Failed to create {msg_type}^{trigger_event} message: {e}")
            # Fallback to simple message
            return self._create_test_message(msg_type, trigger_event)

    def _create_merge_message(self) -> Optional[str]:
        """Create ADT^A40 patient merge message"""
        try:
            version = self._get_version()
            msg = Message("ADT_A40", version=version)

            populate_msh(
                msg,
                self.args,
                version=version,
                msg_type="ADT^A40",
                control_prefix="MRG",
            )

            # Add PID segment (surviving patient - merge TO)
            patient_id = getattr(self.args, "patient_id", None)
            patient_name = getattr(self.args, "patient_name", None)
            pid = self.segment_builder.build_pid(
                patient_id=patient_id or "SURVIVE001",
                patient_name=patient_name or "SURVIVING^PATIENT",
            )
            if pid:
                msg.add(pid)

            # Add MRG segment (patient being merged FROM)
            mrg = self.segment_builder.build_mrg(
                prior_patient_id=getattr(self.args, "merge_patient_id", "MERGE_FROM001"),
                prior_patient_name=getattr(self.args, "merge_patient_name", ""),
                prior_visit_number=getattr(self.args, "merge_visit", ""),
            )
            if mrg:
                msg.add(mrg)

            return msg.to_er7()

        except Exception as e:
            self.logger.debug(f"Failed to create ADT^A40 message: {e}")
            return self._create_test_message("ADT", "A40")
