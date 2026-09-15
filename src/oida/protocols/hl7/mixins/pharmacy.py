"""
HL7 Pharmacy Mixin

Handles pharmacy-related HL7 messages:
- RDE^O11 (Pharmacy Order)
- RAS^O17 (Pharmacy Administration)
- RGV^O15 (Pharmacy Give)
- RDS^O13 (Pharmacy Dispense)
"""

import time
from typing import Optional

from hl7apy.core import Message

from ._helpers import ack_accepted, populate_msh


class PharmacyMixin:
    """Mixin providing HL7 pharmacy message operations."""

    def _send_pharmacy_confirmed(
        self, *, msg_type, label, create_fn, finding_issue, finding_description
    ):
        """Common flow for pharmacy send methods that require --confirm."""
        if not self.require_confirm(
            "--confirm", detail=f"{msg_type} modifies pharmacy records. Use --confirm to proceed."
        ):
            return
        self.logger.display(f"Sending {msg_type} ({label}) message...")

        msg = create_fn()
        if not msg:
            self.logger.fail(f"{msg_type.split('^')[0]} message creation failed")
            return

        response = self._send_mllp_message(msg)
        if response:
            self.logger.success(f"Received {msg_type.split('^')[0]} response")
            self._parse_response(response)
            self._extract_detailed_response(response, msg_type)

            ack = self.results["data"].get("ack_code", "")
            if ack_accepted(ack):
                self.results["data"].setdefault("security_findings", []).append(
                    {
                        "operation": msg_type,
                        "issue": finding_issue,
                        "description": finding_description,
                    }
                )
        else:
            self.logger.warning(f"No response to {msg_type.split('^')[0]} message")

    def _send_rx_message(self):
        """Send RDE^O11 (Pharmacy Order) message with prescription data"""
        drug = getattr(self.args, "rx_drug", None) or "Unknown"
        self._send_pharmacy_confirmed(
            msg_type="RDE^O11",
            label="Pharmacy/Treatment Order",
            create_fn=self._create_rx_message,
            finding_issue="Prescription Order Accepted",
            finding_description=f"Server accepted prescription for {drug} from unknown source",
        )

    def _send_ras_message(self):
        """Send RAS^O17 Pharmacy Administration message"""
        self._send_pharmacy_confirmed(
            msg_type="RAS^O17",
            label="Pharmacy Administration",
            create_fn=self._create_ras_message,
            finding_issue="Pharmacy Administration Accepted",
            finding_description="Server accepted pharmacy administration record - could log fake administrations",
        )

    def _send_rgv_message(self):
        """Send RGV^O15 Pharmacy Give message"""
        self._send_pharmacy_confirmed(
            msg_type="RGV^O15",
            label="Pharmacy Give",
            create_fn=self._create_rgv_message,
            finding_issue="Pharmacy Give Accepted",
            finding_description="Server accepted pharmacy give record - could log fake medication dispensing",
        )

    def _send_rds_message(self):
        """Send RDS^O13 Pharmacy Dispense message"""
        self._send_pharmacy_confirmed(
            msg_type="RDS^O13",
            label="Pharmacy Dispense",
            create_fn=self._create_rds_message,
            finding_issue="Pharmacy Dispense Accepted",
            finding_description="Server accepted pharmacy dispense record - could log fake dispensing",
        )

    def _create_rx_message(self) -> Optional[str]:
        """Create RDE^O11 pharmacy/prescription order message"""
        try:
            version = self._get_version()
            msg = Message("RDE_O11", version=version)

            populate_msh(
                msg,
                self.args,
                version=version,
                msg_type="RDE^O11",
                control_prefix="RX",
                receiving_app="PHARMACY",
            )

            patient_id = getattr(self.args, "patient_id", None)
            patient_name = getattr(self.args, "patient_name", None)
            pid = self.segment_builder.build_pid(
                patient_id=patient_id or "RX_TEST001",
                patient_name=patient_name or "TEST^PATIENT",
                dob=(getattr(self.args, "patient_dob", None) or "19800101"),
                sex=(getattr(self.args, "patient_sex", None) or "U"),
            )
            if pid:
                msg.add(pid)

            orc = self.segment_builder.build_orc(
                order_control="NW",
                placer_order=f"RX{int(time.time())}",
            )
            if orc:
                msg.add(orc)

            rxo = self.segment_builder.build_rxo(
                drug_code=(getattr(self.args, "rx_code", None) or ""),
                drug_name=(getattr(self.args, "rx_drug", None) or "Test Drug"),
                requested_dose=(getattr(self.args, "rx_dose", None) or "10"),
                requested_units=(getattr(self.args, "rx_units", None) or "mg"),
                requested_route=(getattr(self.args, "rx_route", None) or "PO"),
                admin_instructions=(getattr(self.args, "rx_instructions", None) or ""),
                dispense_amount=(getattr(self.args, "rx_quantity", None) or "30"),
                refills=(getattr(self.args, "rx_refills", None) or "0"),
                ordering_provider=(getattr(self.args, "rx_provider", None) or ""),
            )
            if rxo:
                msg.add(rxo)

            return msg.to_er7()

        except Exception as e:
            self.logger.debug(f"Failed to create RDE^O11 message: {e}")
            return self._create_test_message("RDE", "O11")

    def _create_ras_message(self) -> Optional[str]:
        """Create RAS^O17 Pharmacy Administration message"""
        try:
            version = self._get_version()
            msg = Message("RAS_O17", version=version)

            populate_msh(
                msg,
                self.args,
                version=version,
                msg_type="RAS^O17",
                control_prefix="RAS",
                receiving_app="PHARMACY",
            )

            pid = self.segment_builder.build_pid(
                patient_id=getattr(self.args, "patient_id", None) or "ADMIN_TEST001",
                patient_name=getattr(self.args, "patient_name", None) or "TEST^PATIENT",
            )
            if pid:
                msg.add(pid)

            orc = self.segment_builder.build_orc(
                order_control="RE",
                placer_order=f"ADM{int(time.time())}",
            )
            if orc:
                msg.add(orc)

            admin_code = (getattr(self.args, "admin_code", None) or "") or (
                getattr(self.args, "rx_code", None) or ""
            )
            admin_amount = (getattr(self.args, "admin_amount", None) or "") or (
                getattr(self.args, "rx_dose", None) or ""
            )
            rxa = self.segment_builder.build_rxa(
                admin_code=admin_code,
                admin_amount=admin_amount,
                admin_units=(getattr(self.args, "admin_units", None) or "")
                or (getattr(self.args, "rx_units", None) or "mg"),
                completion_status=getattr(self.args, "completion_status", "CP"),
            )
            if rxa:
                msg.add(rxa)

            return msg.to_er7()

        except Exception as e:
            self.logger.debug(f"Failed to create RAS^O17 message: {e}")
            return self._create_test_message("RAS", "O17")

    def _create_rgv_message(self) -> Optional[str]:
        """Create RGV^O15 Pharmacy Give message"""
        try:
            version = self._get_version()
            msg = Message("RGV_O15", version=version)

            populate_msh(
                msg,
                self.args,
                version=version,
                msg_type="RGV^O15",
                control_prefix="RGV",
                receiving_app="PHARMACY",
            )

            pid = self.segment_builder.build_pid(
                patient_id=getattr(self.args, "patient_id", None) or "GIVE_TEST001",
                patient_name=getattr(self.args, "patient_name", None) or "TEST^PATIENT",
            )
            if pid:
                msg.add(pid)

            orc = self.segment_builder.build_orc(
                order_control="RE",
                placer_order=f"GIV{int(time.time())}",
            )
            if orc:
                msg.add(orc)

            give_code = (getattr(self.args, "admin_code", None) or "") or (
                getattr(self.args, "rx_code", None) or ""
            )
            give_amount = (getattr(self.args, "admin_amount", None) or "") or (
                getattr(self.args, "rx_dose", None) or ""
            )
            rxg = self.segment_builder.build_rxg(
                give_code=give_code,
                drug_name=(getattr(self.args, "rx_drug", None) or ""),
                give_amount=give_amount,
                give_units=(getattr(self.args, "admin_units", None) or "")
                or (getattr(self.args, "rx_units", None) or "mg"),
                give_dosage_form=(getattr(self.args, "rx_route", None) or ""),
            )
            if rxg:
                msg.add(rxg)

            return msg.to_er7()

        except Exception as e:
            self.logger.debug(f"Failed to create RGV^O15 message: {e}")
            return self._create_test_message("RGV", "O15")

    def _create_rds_message(self) -> Optional[str]:
        """Create RDS^O13 Pharmacy Dispense message"""
        try:
            version = self._get_version()
            msg = Message("RDS_O13", version=version)

            populate_msh(
                msg,
                self.args,
                version=version,
                msg_type="RDS^O13",
                control_prefix="RDS",
                receiving_app="PHARMACY",
            )

            pid = self.segment_builder.build_pid(
                patient_id=getattr(self.args, "patient_id", None) or "DISP_TEST001",
                patient_name=getattr(self.args, "patient_name", None) or "TEST^PATIENT",
            )
            if pid:
                msg.add(pid)

            orc = self.segment_builder.build_orc(
                order_control="RE",
                placer_order=f"DSP{int(time.time())}",
            )
            if orc:
                msg.add(orc)

            dispense_code = (getattr(self.args, "admin_code", None) or "") or (
                getattr(self.args, "rx_code", None) or ""
            )
            dispense_amount = (getattr(self.args, "dispense_amount", None) or "") or (
                getattr(self.args, "rx_quantity", None) or ""
            )
            rxd = self.segment_builder.build_rxd(
                dispense_code=dispense_code,
                actual_amount=dispense_amount,
                actual_units=(getattr(self.args, "dispense_units", None) or "")
                or (getattr(self.args, "rx_units", None) or ""),
                prescription_number=f"RX{int(time.time())}",
                refills_remaining=(getattr(self.args, "rx_refills", None) or "0"),
            )
            if rxd:
                msg.add(rxd)

            return msg.to_er7()

        except Exception as e:
            self.logger.debug(f"Failed to create RDS^O13 message: {e}")
            return self._create_test_message("RDS", "O13")
