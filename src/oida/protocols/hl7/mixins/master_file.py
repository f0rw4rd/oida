"""
HL7 Master File Mixin

Handles MFN/MFQ master file operations:
- MFN (Master File Notification) messages
- MFQ (Master File Query) messages
- Master file result extraction
"""

import time
from typing import Optional

from hl7apy.core import Message

from ..segments import HL7SegmentParser
from ._helpers import ack_accepted, build_qrd, populate_msh


class MasterFileMixin:
    """Mixin providing HL7 master file operations."""

    def _send_mfn_message(self):
        """Send MFN (Master File Notification) message"""
        mfn_type = getattr(self.args, "mfn_type", "M01")

        # MFN messages modify master files - require --confirm
        if not self.require_confirm(
            "--confirm",
            detail=f"MFN^{mfn_type} (Master File Notification) modifies master data. "
            "Use --confirm to proceed.",
        ):
            return
        type_desc = {
            "M01": "General Master File",
            "M02": "Staff/Practitioner Master File",
            "M04": "Charge Description Master File",
        }
        desc = type_desc.get(mfn_type, "Master File")

        self.logger.display(f"Sending MFN^{mfn_type} ({desc}) message...")

        msg = self._create_mfn_message(mfn_type)
        if msg:
            response = self._send_mllp_message(msg)
            if response:
                self.logger.success(f"Received MFN^{mfn_type} response")
                self._parse_response(response)
                self._extract_mfn_results(response)

                # Security check - master file modification accepted
                ack = self.results["data"].get("ack_code", "")
                if ack_accepted(ack):
                    self.results["data"].setdefault("security_findings", []).append(
                        {
                            "operation": f"MFN^{mfn_type}",
                            "issue": f"Master File Modification Accepted ({desc})",
                            "description": "Server accepted master file update from unknown source",
                            "recommendation": "Implement sender validation for master file messages",
                        }
                    )
            else:
                self.logger.warning(f"No response to MFN^{mfn_type} message")

    def _create_mfn_message(self, mfn_type: str) -> Optional[str]:
        """Create MFN (Master File Notification) message"""
        try:
            version = self._get_version()
            msg_structure = f"MFN_{mfn_type}"
            msg = Message(msg_structure, version=version)

            populate_msh(
                msg,
                self.args,
                version=version,
                msg_type=f"MFN^{mfn_type}",
                control_prefix="MFN",
            )

            # MFI segment (Master File Identification)
            master_file_ids = {
                "M01": "ZZZ^General Master File",
                "M02": "STF^Staff Master File",
                "M04": "CDM^Charge Description Master",
            }
            mfi = self.segment_builder.build_mfi(
                master_file_id=master_file_ids.get(mfn_type, "ZZZ^General"),
                file_level_event_code="UPD",
                response_level_code="AL",
            )
            if mfi:
                msg.add(mfi)

            # MFE segment (Master File Entry)
            mfe = self.segment_builder.build_mfe(
                record_level_event_code="MAD",
                mfn_control_id=f"MFE{int(time.time())}",
                primary_key_value=getattr(self.args, "staff_id", None)
                or (getattr(self.args, "charge_code", None) or "TEST001"),
            )
            if mfe:
                msg.add(mfe)

            # Add type-specific segments
            if mfn_type == "M02":
                # STF segment (Staff Identification)
                stf = self.segment_builder.build_stf(
                    staff_id=(getattr(self.args, "staff_id", None) or "STF001"),
                    staff_name=(getattr(self.args, "staff_name", None) or "TEST^STAFF"),
                    staff_type=(getattr(self.args, "staff_type", None) or "MD"),
                    department=getattr(self.args, "department", ""),
                    active_inactive="A",
                )
                if stf:
                    msg.add(stf)

                # PRA segment (Practitioner Detail)
                pra = self.segment_builder.build_pra(
                    practitioner_id=(getattr(self.args, "staff_id", None) or "STF001"),
                    practitioner_category=(getattr(self.args, "staff_type", None) or "MD"),
                )
                if pra:
                    msg.add(pra)

            elif mfn_type == "M04":
                # PRC segment (Pricing/Charge Description)
                prc = self.segment_builder.build_prc(
                    charge_code=(getattr(self.args, "charge_code", None) or "CHG001"),
                    price=(getattr(self.args, "charge_price", None) or "100.00"),
                    active_inactive="A",
                )
                if prc:
                    msg.add(prc)

            return msg.to_er7()

        except Exception as e:
            self.logger.debug(f"Failed to create MFN^{mfn_type} message: {e}")
            return self._create_test_message("MFN", mfn_type)

    def _send_mfq_message(self):
        """Send MFQ^M01 (Master File Query) message"""
        self.logger.display("Sending MFQ^M01 (Master File Query) message...")

        msg = self._create_mfq_message()
        if msg:
            response = self._send_mllp_message(msg)
            if response:
                self.logger.success("Received MFR (Master File Response)")
                self._parse_response(response)
                self._extract_mfn_results(response)
            else:
                self.logger.warning("No response to MFQ message")

    def _create_mfq_message(self) -> Optional[str]:
        """Create MFQ^M01 (Master File Query) message"""
        try:
            version = self._get_version()
            msg = Message("MFQ_M01", version=version)

            populate_msh(
                msg,
                self.args,
                version=version,
                msg_type="MFQ^M01",
                control_prefix="MFQ",
            )

            qrd = build_qrd(
                version,
                query_id_prefix="MFQ",
                result_format="RD",
                who_subject="*",
                what_subject="MFI",
            )
            msg.add(qrd)

            return msg.to_er7()

        except Exception as e:
            self.logger.debug(f"Failed to create MFQ^M01 message: {e}")
            return self._create_test_message("MFQ", "M01")

    def _extract_mfn_results(self, response: bytes):
        """Extract master file data from MFR/MFK response"""
        try:
            segments = HL7SegmentParser.split_message(response)
            master_files = []
            staff_entries = []
            charge_entries = []

            for segment in segments:
                if segment.startswith("MFI|"):
                    mfi = HL7SegmentParser.parse_mfi(segment)
                    if mfi.get("MasterFileID"):
                        master_files.append(mfi)

                elif segment.startswith("STF|"):
                    stf = HL7SegmentParser.parse_stf(segment)
                    # parse_stf returns 'StaffID', not 'StaffIDCode' — the
                    # old key matched nothing so accepted staff segments
                    # were silently dropped.
                    if stf.get("StaffID") or stf.get("StaffName"):
                        staff_entries.append(stf)

                elif segment.startswith("PRC|"):
                    prc = HL7SegmentParser.parse_prc(segment)
                    if prc.get("PrimaryKeyValue"):
                        charge_entries.append(prc)

            # Display and store results
            if master_files:
                self.logger.display(f"Master Files ({len(master_files)}):")
                for mf in master_files[:10]:
                    self.logger.display(f"  - {mf.get('MasterFileID', 'Unknown')}")

            if staff_entries:
                column_defs = [
                    ("StaffID", "Staff ID"),
                    ("StaffName", "Name"),
                    ("StaffType", "Type"),
                    ("Department", "Dept"),
                    ("ActiveStatus", "Status"),
                ]
                self._display_results_table(
                    items=staff_entries,
                    column_defs=column_defs,
                    result_key="staff_entries",
                    result_label="staff member(s)",
                    security_finding={
                        "operation": "MFN",
                        "issue": "Staff Master File Accessible",
                        "description": f"Query returned {len(staff_entries)} staff records",
                    },
                )

            if charge_entries:
                # 'ActiveInactiveFlag' was never in parse_prc's return —
                # the column rendered blank every run. PRC doesn't carry a
                # status flag in v2.5; dropped the column.
                column_defs = [
                    ("PrimaryKeyValue", "Charge Code"),
                    ("Price", "Price"),
                    ("Department", "Dept"),
                    ("EffectiveStartDate", "Effective"),
                    ("EffectiveEndDate", "Expires"),
                ]
                self._display_results_table(
                    items=charge_entries,
                    column_defs=column_defs,
                    result_key="charge_entries",
                    result_label="charge code(s)",
                )

            self.results["data"]["master_file_results"] = {
                "master_files": master_files,
                "staff_entries": staff_entries,
                "charge_entries": charge_entries,
            }

        except Exception as e:
            self.logger.debug(f"Failed to extract master file results: {e}")
