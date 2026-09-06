"""
HL7 Response Mixin

Handles response parsing and data extraction:
- Detailed response extraction
- Query result extraction (patients)
- Observation result extraction (labs/vitals)
- Pharmacy result extraction (medications)
- Order status extraction
"""

from datetime import datetime

from hl7apy.parser import parse_message

from ..segments import HL7SegmentParser


class ResponseMixin:
    """Mixin providing HL7 response parsing and data extraction."""

    def _extract_detailed_response(self, response: bytes, msg_type: str):
        """Extract detailed data from response if --extract-response is set"""
        if not getattr(self.args, "extract_response", False):
            return

        try:
            msg_str = response.decode("utf-8", errors="ignore")
            msg = parse_message(msg_str)

            extracted = {
                "message_type": msg_type,
                "timestamp": datetime.now().isoformat(),
                # Store the raw response bytes so the enumeration mixins
                # (_enum_providers/_enum_apps/_enum_locations) can re-parse
                # previously collected responses. Without this key their
                # "also extract from stored responses" loop is dead code.
                "raw": response,
                "segments": {},
            }

            # Extract specific fields if requested
            extract_fields = getattr(self.args, "extract_fields", "")
            if extract_fields:
                for field_spec in extract_fields.split(","):
                    field_spec = field_spec.strip()
                    if "-" in field_spec:
                        seg_name, field_num = field_spec.split("-", 1)
                        seg_name = seg_name.lower()
                        if hasattr(msg, seg_name):
                            seg = getattr(msg, seg_name)
                            field_name = f"{seg_name}_{field_num}"
                            value = self._get_field_value(seg, field_name)
                            extracted["segments"][field_spec] = value
                            self.logger.display(f"  {field_spec}: {value}")
            else:
                # Extract common fields (only display if non-empty)
                if hasattr(msg, "pid"):
                    pid = msg.pid
                    extracted["segments"]["PID-3"] = self._get_field_value(pid, "pid_3")
                    extracted["segments"]["PID-5"] = self._get_field_value(pid, "pid_5")
                    if extracted["segments"]["PID-3"]:
                        self.logger.display(f"  Patient ID: {extracted['segments']['PID-3']}")
                    if extracted["segments"]["PID-5"]:
                        self.logger.display(f"  Patient Name: {extracted['segments']['PID-5']}")

                if hasattr(msg, "pv1"):
                    pv1 = msg.pv1
                    extracted["segments"]["PV1-2"] = self._get_field_value(pv1, "pv1_2")
                    extracted["segments"]["PV1-19"] = self._get_field_value(pv1, "pv1_19")

            self.all_responses.append(extracted)

        except Exception as e:
            self.logger.debug(f"Failed to extract response data: {e}")

    def _extract_query_results(self, response: bytes):
        """Extract patient data from query response (RSP message)"""
        try:
            extract_all = getattr(self.args, "extract_response", False)
            parsed = HL7SegmentParser.parse_message(response, extended=extract_all)
            patients_found = parsed["patients"]

            # Build column definitions - core fields first, then extended
            core_columns = [
                ("PatientID", "ID"),
                ("PatientName", "Name"),
                ("DOB", "DOB"),
                ("Sex", "Sex"),
                ("Address", "Address"),
                ("Phone", "Phone"),
                ("Account", "Account"),
            ]
            ext_columns = [
                ("AltID", "Alt ID"),
                ("MaidenName", "Maiden"),
                ("Alias", "Alias"),
                ("Race", "Race"),
                ("County", "County"),
                ("BusinessPhone", "Bus Phone"),
                ("Language", "Lang"),
                ("MaritalStatus", "Marital"),
                ("Religion", "Religion"),
                ("SSN", "SSN"),
                ("DriversLicense", "DL"),
                ("EthnicGroup", "Ethnicity"),
            ]
            column_defs = core_columns + (ext_columns if extract_all else [])

            # _display_results_table is the single writer of query_results
            # below; the previous direct write here was immediately clobbered
            # by it (and used a different item key), so it is removed.
            self._display_results_table(
                items=patients_found,
                column_defs=column_defs,
                result_key="query_results",
                result_label="patient(s)",
                security_finding={
                    "operation": "QRY",
                    "issue": "Unrestricted Query Access",
                    "description": f"Query returned {len(patients_found)} patient records",
                }
                if patients_found
                else None,
            )

        except Exception as e:
            self.logger.debug(f"Failed to extract query results: {e}")

    def _extract_observation_results(self, response: bytes):
        """Extract observation/lab results from ORF^R04 response"""
        try:
            parsed = HL7SegmentParser.parse_message(response)
            observations = parsed["observations"]

            column_defs = [
                ("PatientID", "Patient"),
                ("ObservationID", "Test ID"),
                ("ObservationName", "Test Name"),
                ("Value", "Value"),
                ("Units", "Units"),
                ("RefRange", "Ref Range"),
                ("AbnormalFlag", "Flag"),
                ("Status", "Status"),
            ]

            self._display_results_table(
                items=observations,
                column_defs=column_defs,
                result_key="observation_results",
                result_label="observation(s)",
                security_finding={
                    "operation": "QRY^R02",
                    "issue": "Observation Results Accessible",
                    "description": f"Query returned {len(observations)} lab/observation results",
                }
                if observations
                else None,
            )

        except Exception as e:
            self.logger.debug(f"Failed to extract observation results: {e}")

    def _extract_pharmacy_results(self, response: bytes):
        """Extract pharmacy/medication data from RSP^K31 or RDR response"""
        try:
            parsed = HL7SegmentParser.parse_message(response)
            medications = parsed["medications"]

            column_defs = [
                ("PatientID", "Patient"),
                ("DrugCode", "Drug Code"),
                ("DrugName", "Drug Name"),
                ("Dose", "Dose"),
                ("Units", "Units"),
                ("Route", "Route"),
                ("Quantity", "Qty"),
                ("Refills", "Refills"),
                ("DispenseDate", "Dispensed"),
                ("AdminDate", "Administered"),
                ("LotNumber", "Lot#"),
                ("Manufacturer", "Mfr"),
                ("Status", "Status"),
            ]

            self._display_results_table(
                items=medications,
                column_defs=column_defs,
                result_key="pharmacy_results",
                result_label="medication(s)",
                security_finding={
                    "operation": "QBP^Q31",
                    "issue": "Pharmacy Dispense History Accessible",
                    "description": f"Query returned {len(medications)} medication records",
                }
                if medications
                else None,
            )

        except Exception as e:
            self.logger.debug(f"Failed to extract pharmacy results: {e}")

    def _extract_order_status(self, response: bytes):
        """Extract order status from OSR^Q06 response"""
        try:
            parsed = HL7SegmentParser.parse_message(response)
            # parse_message now returns 'orders' (added alongside the OBR/ORC
            # collection fix). Keys come from parse_orc + parse_obr.
            orders = parsed.get("orders", [])

            column_defs = [
                ("PatientID", "Patient"),
                ("PlacerOrderNumber", "Placer Order"),
                ("FillerOrderNumber", "Filler Order"),
                ("UniversalServiceID", "Service ID"),
                ("OrderStatus", "Status"),
                ("Priority", "Priority"),
                ("RequestedDateTime", "Requested"),
                ("OrderingProvider", "Provider"),
                ("ResultStatus", "Result"),
            ]

            self._display_results_table(
                items=orders,
                column_defs=column_defs,
                result_key="order_status_results",
                result_label="order(s)",
                security_finding={
                    "operation": "OSQ^Q06",
                    "issue": "Order Status Query Accessible",
                    "description": f"Query returned {len(orders)} order records",
                }
                if orders
                else None,
            )

        except Exception as e:
            self.logger.debug(f"Failed to extract order status: {e}")
