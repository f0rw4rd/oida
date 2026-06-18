"""
DICOM Worklist Mixin

Handles Modality Worklist (MWL) queries, result extraction, and display.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..nxc_connection import _new_dataset, _sop

if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


class WorklistMixin(_ScannerBase):
    """Mixin providing Modality Worklist operations for the DICOM scanner."""

    def _worklist_query(self):
        """
        Query Modality Worklist for scheduled procedures.

        MWL provides access to scheduled procedures and patient demographics,
        which is valuable for pentesting reconnaissance.
        """
        if not self.assoc or not self.assoc.is_established:
            self.logger.fail("No active association for Worklist query")
            return

        self.logger.display("Querying Modality Worklist for scheduled procedures...")

        modality_filter = getattr(self.args, "worklist_modality", "")
        date_filter = getattr(self.args, "worklist_date", "")
        station_filter = getattr(self.args, "worklist_station", "")
        max_results = getattr(self.args, "max_results", 100)

        scheduled_procedures = []

        try:
            # Build Worklist query dataset
            ds = _new_dataset()

            # ScheduledProcedureStepSequence - the core of MWL
            ds.ScheduledProcedureStepSequence = [_new_dataset()]
            step = ds.ScheduledProcedureStepSequence[0]

            # Filter by modality if specified
            if modality_filter:
                step.Modality = modality_filter
            else:
                step.Modality = ""  # Return key

            # Filter by date if specified
            if date_filter:
                step.ScheduledProcedureStepStartDate = date_filter
            else:
                step.ScheduledProcedureStepStartDate = ""  # Return key

            # Filter by station if specified
            if station_filter:
                step.ScheduledStationAETitle = station_filter
            else:
                step.ScheduledStationAETitle = ""  # Return key

            # Return keys for step info
            step.ScheduledProcedureStepStartTime = ""
            step.ScheduledPerformingPhysicianName = ""
            step.ScheduledProcedureStepDescription = ""
            step.ScheduledProcedureStepID = ""
            step.ScheduledStationName = ""

            # Patient level filters/returns
            ds.PatientName = "*"  # Wildcard to get all
            ds.PatientID = ""
            ds.PatientBirthDate = ""
            ds.PatientSex = ""
            ds.RequestedProcedureID = ""
            ds.AccessionNumber = ""
            ds.ReferringPhysicianName = ""
            ds.RequestingPhysician = ""
            ds.StudyInstanceUID = ""

            # Send C-FIND to Modality Worklist
            responses = self.assoc.send_c_find(
                ds,
                _sop("ModalityWorklistInformationFind"),
            )

            count = 0
            for status, identifier in responses:
                if status and status.Status in (0xFF00, 0xFF01):  # Pending
                    if identifier:
                        result = self._extract_worklist_result(identifier)
                        scheduled_procedures.append(result)

                        if count < 10:  # Display first 10
                            self._display_worklist_result(result)

                        count += 1
                        if count >= max_results:
                            self.logger.warning(f"Reached max results limit ({max_results})")
                            break

            self.logger.display(f"Worklist Results: {count} scheduled procedures found")

            # Security assessment
            if count > 0:
                if not modality_filter and not date_filter and not station_filter:
                    self.logger.security_finding(
                        "Unrestricted worklist access",
                        f"Worklist query returned {count} scheduled procedures without filters",
                    )

            # Store results
            self.results["data"]["worklist_results"] = {
                "count": count,
                "procedures": scheduled_procedures[:50],
                "modality_filter": modality_filter,
                "date_filter": date_filter,
                "station_filter": station_filter,
            }

        except Exception as e:
            error_msg = str(e)
            if "No accepted presentation context" in error_msg:
                self.logger.warning("Worklist (MWL) not supported by this server")
            else:
                self.logger.fail(f"Worklist query failed: {e}")

    def _extract_worklist_result(self, identifier) -> dict:
        """Extract scheduled procedure information from Worklist response"""
        result = {}

        # Patient level
        result["PatientName"] = str(getattr(identifier, "PatientName", ""))
        result["PatientID"] = str(getattr(identifier, "PatientID", ""))
        result["PatientBirthDate"] = str(getattr(identifier, "PatientBirthDate", ""))
        result["PatientSex"] = str(getattr(identifier, "PatientSex", ""))
        result["AccessionNumber"] = str(getattr(identifier, "AccessionNumber", ""))
        result["ReferringPhysician"] = str(getattr(identifier, "ReferringPhysicianName", ""))
        result["RequestingPhysician"] = str(getattr(identifier, "RequestingPhysician", ""))
        result["RequestedProcedureID"] = str(getattr(identifier, "RequestedProcedureID", ""))
        result["StudyInstanceUID"] = str(getattr(identifier, "StudyInstanceUID", ""))

        # Scheduled Procedure Step Sequence
        if hasattr(identifier, "ScheduledProcedureStepSequence"):
            step_list = []
            for step in identifier.ScheduledProcedureStepSequence:
                step_dict = {
                    "StationAETitle": str(getattr(step, "ScheduledStationAETitle", "")),
                    "StationName": str(getattr(step, "ScheduledStationName", "")),
                    "Modality": str(getattr(step, "Modality", "")),
                    "ProcedureStepID": str(getattr(step, "ScheduledProcedureStepID", "")),
                    "Description": str(getattr(step, "ScheduledProcedureStepDescription", "")),
                    "StartDate": str(getattr(step, "ScheduledProcedureStepStartDate", "")),
                    "StartTime": str(getattr(step, "ScheduledProcedureStepStartTime", "")),
                    "PerformingPhysician": str(
                        getattr(step, "ScheduledPerformingPhysicianName", "")
                    ),
                }
                step_list.append(step_dict)
            result["ScheduledSteps"] = step_list

        return result

    def _display_worklist_result(self, result: dict):
        """Display a scheduled procedure from Worklist"""
        patient = result.get("PatientName", "Unknown")
        patient_id = result.get("PatientID", "")
        accession = result.get("AccessionNumber", "")
        referring = result.get("ReferringPhysician", "")

        acc_str = f", Acc: {accession}" if accession else ""
        self.logger.display(f"  Scheduled: {patient} (ID: {patient_id}{acc_str})")

        if result.get("ScheduledSteps"):
            for step in result["ScheduledSteps"]:
                modality = step.get("Modality", "")
                station = step.get("StationAETitle", "")
                date = step.get("StartDate", "")
                time = step.get("StartTime", "")[:6] if step.get("StartTime") else ""
                physician = step.get("PerformingPhysician", "")
                desc = step.get("Description", "")

                # Format date/time
                if date and len(date) == 8:
                    date_fmt = f"{date[:4]}-{date[4:6]}-{date[6:8]}"
                else:
                    date_fmt = date

                if time and len(time) >= 4:
                    time_fmt = f"{time[:2]}:{time[2:4]}"
                else:
                    time_fmt = ""

                datetime_str = f"{date_fmt} {time_fmt}".strip()

                self.logger.display(f"    -> {modality} | {desc or 'N/A'} | {datetime_str}")
                if station:
                    self.logger.display(f"       Station: {station}")
                if physician:
                    self.logger.display(f"       Physician: {physician}")

        if referring:
            self.logger.display(f"    Referring: {referring}")
