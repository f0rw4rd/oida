"""
HL7 Financial Mixin

Handles BAR/DFT financial messages:
- BAR^P01 (Add Billing Account)
- DFT^P03 (Post Financial Transaction)
- Financial result extraction
"""

import time
from datetime import datetime
from typing import Optional

from hl7apy.core import Message, Segment

from ..segments import HL7SegmentParser
from ._helpers import populate_msh


class FinancialMixin:
    """Mixin providing HL7 financial message operations."""

    def _send_bar_message(self):
        """Send BAR^P01 (Add Billing Account) message"""
        if not getattr(self.args, "confirm", False):
            self.logger.fail(
                "BAR^P01 (Add Billing Account) is a write operation. Use --confirm to proceed."
            )
            return

        self.logger.display("Sending BAR^P01 (Add Billing Account) message...")

        msg = self._create_bar_message()
        if msg:
            response = self._send_mllp_message(msg)
            if response:
                self.logger.success("Received BAR^P01 response")
                self._parse_response(response)
                self._extract_financial_results(response)

                ack = self.results["data"].get("ack_code", "")
                if ack == "AA":
                    self.results["data"].setdefault("security_findings", []).append(
                        {
                            "severity": "HIGH",
                            "operation": "BAR^P01",
                            "issue": "Billing Account Creation Accepted",
                            "description": "Server accepted billing account from unknown source",
                            "recommendation": "Implement sender validation for financial messages",
                        }
                    )
            else:
                self.logger.warning("No response to BAR^P01 message")

    def _send_dft_message(self):
        """Send DFT^P03 (Post Financial Transaction) message"""
        if not getattr(self.args, "confirm", False):
            self.logger.fail(
                "DFT^P03 (Post Financial Transaction) is a write operation. "
                "Use --confirm to proceed."
            )
            return

        self.logger.display("Sending DFT^P03 (Post Financial Transaction) message...")

        msg = self._create_dft_message()
        if msg:
            response = self._send_mllp_message(msg)
            if response:
                self.logger.success("Received DFT^P03 response")
                self._parse_response(response)
                self._extract_financial_results(response)

                ack = self.results["data"].get("ack_code", "")
                if ack == "AA":
                    amount = getattr(self.args, "transaction_amount", "Unknown")
                    self.results["data"].setdefault("security_findings", []).append(
                        {
                            "severity": "HIGH",
                            "operation": "DFT^P03",
                            "issue": "Financial Transaction Accepted",
                            "description": f"Server accepted financial transaction (${amount}) from unknown source",
                            "recommendation": "Implement sender validation for financial messages",
                        }
                    )
            else:
                self.logger.warning("No response to DFT^P03 message")

    def _add_financial_common_segments(
        self, msg: Message, *, evn_code: str, default_patient_id: str, default_patient_name: str
    ):
        """Add common EVN, PID, PV1 segments shared by BAR and DFT messages.

        Args:
            msg: HL7 Message to add segments to.
            evn_code: EVN-1 event type code (e.g. "P01", "P03").
            default_patient_id: Fallback patient ID.
            default_patient_name: Fallback patient name.

        Returns:
            Tuple of (patient_id, patient_name) actually used.
        """
        version = msg.msh.msh_12.value if hasattr(msg.msh.msh_12, "value") else str(msg.msh.msh_12)

        # EVN segment
        evn = Segment("EVN", version=version)
        evn.evn_1 = evn_code
        evn.evn_2 = datetime.now().strftime("%Y%m%d%H%M%S")
        msg.add(evn)

        # PID segment
        patient_id = getattr(self.args, "patient_id", None)
        patient_name = getattr(self.args, "patient_name", None)
        pid = self.segment_builder.build_pid(
            patient_id=patient_id or default_patient_id,
            patient_name=patient_name or default_patient_name,
        )
        if pid:
            msg.add(pid)

        # PV1 segment
        pv1 = self.segment_builder.build_pv1(
            patient_class=getattr(self.args, "patient_class", "O"),
            visit_number=getattr(self.args, "visit_number", f"VIS{int(time.time())}"),
        )
        if pv1:
            msg.add(pv1)

        return patient_id, patient_name

    def _create_bar_message(self) -> Optional[str]:
        """Create BAR^P01 (Add Billing Account) message"""
        try:
            version = self._get_version()
            msg = Message("BAR_P01", version=version)

            populate_msh(
                msg,
                self.args,
                version=version,
                msg_type="BAR^P01",
                control_prefix="BAR",
                receiving_app="BILLING",
            )

            patient_id, patient_name = self._add_financial_common_segments(
                msg,
                evn_code="P01",
                default_patient_id="BAR_TEST001",
                default_patient_name="TEST^BILLING",
            )

            # GT1 segment (Guarantor)
            gt1 = self.segment_builder.build_gt1(
                guarantor_number=getattr(self.args, "account_number", f"GT{int(time.time())}"),
                guarantor_name=getattr(
                    self.args, "guarantor_name", patient_name or "TEST^GUARANTOR"
                ),
                guarantor_phone=getattr(self.args, "guarantor_phone", ""),
            )
            if gt1:
                msg.add(gt1)

            # IN1 segment (Insurance)
            insurance_company = getattr(self.args, "insurance_company", None)
            if insurance_company:
                in1 = self.segment_builder.build_in1(
                    insurance_company_name=insurance_company,
                    group_number=getattr(self.args, "insurance_group", ""),
                    policy_number=getattr(self.args, "policy_number", ""),
                )
                if in1:
                    msg.add(in1)

            return msg.to_er7()

        except Exception as e:
            self.logger.debug(f"Failed to create BAR^P01 message: {e}")
            return self._create_test_message("BAR", "P01")

    def _create_dft_message(self) -> Optional[str]:
        """Create DFT^P03 (Post Financial Transaction) message"""
        try:
            version = self._get_version()
            msg = Message("DFT_P03", version=version)

            populate_msh(
                msg,
                self.args,
                version=version,
                msg_type="DFT^P03",
                control_prefix="DFT",
                receiving_app="BILLING",
            )

            patient_id, _ = self._add_financial_common_segments(
                msg,
                evn_code="P03",
                default_patient_id="DFT_TEST001",
                default_patient_name="TEST^FINANCIAL",
            )

            # FT1 segment (Financial Transaction)
            ft1 = self.segment_builder.build_ft1(
                transaction_id=f"FT{int(time.time())}",
                transaction_type=getattr(self.args, "transaction_type", "CG"),
                transaction_code=getattr(self.args, "transaction_code", "99213"),
                transaction_description=getattr(self.args, "transaction_description", None)
                or "Office Visit",
                transaction_amount=getattr(self.args, "transaction_amount", "100.00"),
                patient_id=patient_id or "DFT_TEST001",
                diagnosis_code=getattr(self.args, "dx_code", ""),
                procedure_code=getattr(self.args, "pr_code", ""),
            )
            if ft1:
                msg.add(ft1)

            return msg.to_er7()

        except Exception as e:
            self.logger.debug(f"Failed to create DFT^P03 message: {e}")
            return self._create_test_message("DFT", "P03")

    def _extract_financial_results(self, response: bytes):
        """Extract financial data from BAR/DFT response"""
        try:
            segments = HL7SegmentParser.split_message(response)
            transactions = []
            guarantors = []
            insurance = []

            for segment in segments:
                if segment.startswith("FT1|"):
                    ft1 = HL7SegmentParser.parse_ft1(segment)
                    if ft1.get("TransactionID") or ft1.get("TransactionAmount"):
                        transactions.append(ft1)

                elif segment.startswith("GT1|"):
                    gt1 = HL7SegmentParser.parse_gt1(segment)
                    if gt1.get("GuarantorNumber") or gt1.get("GuarantorName"):
                        guarantors.append(gt1)

                elif segment.startswith("IN1|"):
                    in1 = HL7SegmentParser.parse_in1(segment)
                    if in1.get("InsuranceCompanyName") or in1.get("InsurancePlanID"):
                        insurance.append(in1)

            if transactions:
                column_defs = [
                    ("TransactionID", "Trans ID"),
                    ("TransactionType", "Type"),
                    ("TransactionCode", "Code"),
                    ("TransactionDescription", "Desc"),
                    ("TransactionAmount", "Amount"),
                    ("TransactionDate", "Date"),
                ]
                self._display_results_table(
                    items=transactions,
                    column_defs=column_defs,
                    result_key="financial_transactions",
                    result_label="transaction(s)",
                )

            if guarantors:
                column_defs = [
                    ("GuarantorNumber", "Number"),
                    ("GuarantorName", "Name"),
                    ("GuarantorPhone", "Phone"),
                    ("GuarantorRelationship", "Relationship"),
                ]
                self._display_results_table(
                    items=guarantors,
                    column_defs=column_defs,
                    result_key="guarantors",
                    result_label="guarantor(s)",
                )

            if insurance:
                column_defs = [
                    ("InsuranceCompanyName", "Company"),
                    ("GroupNumber", "Group"),
                    ("PolicyNumber", "Policy"),
                    ("InsuredName", "Insured"),
                ]
                self._display_results_table(
                    items=insurance,
                    column_defs=column_defs,
                    result_key="insurance",
                    result_label="insurance record(s)",
                )

            self.results["data"]["financial_results"] = {
                "transactions": transactions,
                "guarantors": guarantors,
                "insurance": insurance,
            }

        except Exception as e:
            self.logger.debug(f"Failed to extract financial results: {e}")
