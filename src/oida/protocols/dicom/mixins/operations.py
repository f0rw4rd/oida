"""
DICOM Operations Mixin

Handles C-GET, C-STORE, C-MOVE, and bulk export operations.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from ..cli_runner import _get_dcmread, _new_dataset, _sop
from oida.utils.common_types import Category

if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


class OperationsMixin(_ScannerBase):
    """Mixin providing C-GET/C-STORE/C-MOVE and bulk export for the DICOM scanner."""

    def _recursive_bulk_export(self):
        """Recursive bulk export: PATIENT -> STUDY -> SERIES -> C-GET all images"""
        if not self.assoc or not self.assoc.is_established:
            self.logger.fail("No active association for bulk export")
            return

        output_dir = getattr(self.args, "output_dir", "./dicom_output")
        max_patients = getattr(self.args, "max_patients", 10)
        max_studies = getattr(self.args, "max_studies", 50)

        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        # Set up instance state for C-STORE handler
        self._cget_output_path = output_path
        self._cget_use_subdirs = True  # Use patient/study subdirectory structure
        self._cget_received_files = []

        self.logger.display(f"Starting recursive bulk export to {output_dir}...")
        self.logger.display(
            f"  Max patients: {max_patients}, Max studies per patient: {max_studies}"
        )

        total_stats = {
            "patients": 0,
            "studies": 0,
            "series": 0,
            "images": 0,
        }

        # Step 1: Find all patients
        self.logger.display("[1/4] Enumerating patients...")
        ds = _new_dataset()
        ds.QueryRetrieveLevel = "PATIENT"
        ds.PatientName = "*"
        ds.PatientID = ""

        patients = []
        try:
            responses = self.assoc.send_c_find(
                ds,
                _sop("PatientRootQueryRetrieveInformationModelFind"),
            )

            for status, identifier in responses:
                if status and status.Status in (0xFF00, 0xFF01) and identifier:
                    patient_id = str(getattr(identifier, "PatientID", ""))
                    patient_name = str(getattr(identifier, "PatientName", ""))
                    if patient_id:
                        patients.append({"id": patient_id, "name": patient_name})
                        if len(patients) >= max_patients:
                            break

            self.logger.display(f"  Found {len(patients)} patients")
            total_stats["patients"] = len(patients)

        except Exception as e:
            self.logger.debug("recursive bulk export failed: %s", e)
            self.logger.fail(f"Patient enumeration failed: {e}")
            return

        # Step 2: For each patient, find studies
        self.logger.display("[2/4] Enumerating studies per patient...")
        all_studies = []

        for patient in patients:
            ds = _new_dataset()
            ds.QueryRetrieveLevel = "STUDY"
            ds.PatientID = patient["id"]
            ds.StudyInstanceUID = ""
            ds.StudyDate = ""
            ds.StudyDescription = ""

            try:
                responses = self.assoc.send_c_find(
                    ds,
                    _sop("PatientRootQueryRetrieveInformationModelFind"),
                )

                study_count = 0
                for status, identifier in responses:
                    if status and status.Status in (0xFF00, 0xFF01) and identifier:
                        study_uid = str(getattr(identifier, "StudyInstanceUID", ""))
                        if study_uid:
                            all_studies.append(
                                {
                                    "patient_id": patient["id"],
                                    "patient_name": patient["name"],
                                    "study_uid": study_uid,
                                    "date": str(getattr(identifier, "StudyDate", "")),
                                }
                            )
                            study_count += 1
                            if study_count >= max_studies:
                                break

                self.logger.display(f"  Patient {patient['id']}: {study_count} studies")

            except Exception as e:
                self.logger.debug(f"Study enumeration failed for {patient['id']}: {e}")

        self.logger.display(f"  Total studies: {len(all_studies)}")
        total_stats["studies"] = len(all_studies)

        # Step 3: For each study, find series
        self.logger.display("[3/4] Enumerating series per study...")
        all_series = []

        for study in all_studies:
            ds = _new_dataset()
            ds.QueryRetrieveLevel = "SERIES"
            ds.StudyInstanceUID = study["study_uid"]
            ds.SeriesInstanceUID = ""
            ds.Modality = ""
            ds.NumberOfSeriesRelatedInstances = ""

            try:
                responses = self.assoc.send_c_find(
                    ds,
                    _sop("PatientRootQueryRetrieveInformationModelFind"),
                )

                for status, identifier in responses:
                    if status and status.Status in (0xFF00, 0xFF01) and identifier:
                        series_uid = str(getattr(identifier, "SeriesInstanceUID", ""))
                        if series_uid:
                            all_series.append(
                                {
                                    "patient_id": study["patient_id"],
                                    "study_uid": study["study_uid"],
                                    "series_uid": series_uid,
                                    "modality": str(getattr(identifier, "Modality", "")),
                                    "instance_count": str(
                                        getattr(identifier, "NumberOfSeriesRelatedInstances", "")
                                    ),
                                }
                            )

            except Exception as e:
                self.logger.debug(
                    f"Series enumeration failed for study {study['study_uid'][:20]}...: {e}"
                )

        self.logger.display(f"  Total series: {len(all_series)}")
        total_stats["series"] = len(all_series)

        # Step 4: Retrieve all images via C-GET
        self.logger.display("[4/4] Retrieving images...")

        for series in all_series:
            ds = _new_dataset()
            ds.QueryRetrieveLevel = "SERIES"
            ds.StudyInstanceUID = series["study_uid"]
            ds.SeriesInstanceUID = series["series_uid"]

            try:
                # Event handler was bound at association time. Retrieve is
                # keyed by Study+Series UID, so use StudyRoot (accepted by
                # StudyRoot-only PACS that reject PatientRoot).
                responses = self.assoc.send_c_get(
                    ds,
                    _sop("StudyRootQueryRetrieveInformationModelGet"),
                )

                for status, identifier in responses:
                    pass  # Just consume responses

            except Exception as e:
                self.logger.debug(f"C-GET failed for series {series['series_uid'][:20]}...: {e}")

        total_stats["images"] = len(self._cget_received_files)

        # Summary
        self.logger.display("=== Bulk Export Complete ===")
        self.logger.display(f"  Patients: {total_stats['patients']}")
        self.logger.display(f"  Studies: {total_stats['studies']}")
        self.logger.display(f"  Series: {total_stats['series']}")
        self.logger.display(f"  Images: {total_stats['images']}")
        self.logger.display(f"  Output: {output_dir}")

        self.results["data"]["bulk_export"] = total_stats

        # Security finding
        if total_stats["images"] > 0:
            self.logger.security_finding(
                "Mass data exfiltration",
                category=Category.ACCESS_CONTROL,
                detail=f"Exported {total_stats['images']} images from {total_stats['patients']} patients",
            )

    def _cget_retrieve(self):
        """Retrieve DICOM images using C-GET"""
        if not self.assoc or not self.assoc.is_established:
            self.logger.fail("No active association for C-GET")
            return

        # Targeted --get writes to a flat output dir. Reset the subdir flag in
        # case a prior --dump-all in the same run set it True (it is never
        # reset otherwise), which would scatter files into patient/study dirs.
        self._cget_use_subdirs = False

        study_uid = getattr(self.args, "study_uid", "")
        series_uid = getattr(self.args, "series_uid", "")
        output_dir = getattr(self.args, "output_dir", "./dicom_output")

        if not study_uid and not series_uid:
            self.logger.fail("C-GET requires --study-uid or --series-uid")
            return

        # Create output directory and set up instance state for handler
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        self._cget_output_path = output_path
        self._cget_received_files = []

        self.logger.display(f"Retrieving images to {output_dir}...")

        # Create identifier dataset
        ds = _new_dataset()
        if series_uid:
            ds.QueryRetrieveLevel = "SERIES"
            ds.SeriesInstanceUID = series_uid
            if study_uid:
                ds.StudyInstanceUID = study_uid
        else:
            ds.QueryRetrieveLevel = "STUDY"
            ds.StudyInstanceUID = study_uid

        try:
            # Use StudyRoot C-GET (event handler was bound at association time).
            # This retrieve is keyed by Study/Series UID with no PatientID, and
            # many StudyRoot-only PACS reject PatientRoot outright — mirrors the
            # model selection cfind.py uses for STUDY/SERIES queries.
            responses = self.assoc.send_c_get(
                ds,
                _sop("StudyRootQueryRetrieveInformationModelGet"),
            )

            # Drain the response generator (files are written by the bound
            # C-STORE handler); only warn on unexpected non-pending/non-success.
            for status, identifier in responses:
                if status and status.Status not in (0xFF00, 0x0000):
                    self.logger.warning(f"C-GET status: 0x{status.Status:04X}")

            self.logger.success(
                f"Retrieved {len(self._cget_received_files)} images to {output_dir}"
            )

            self.results["data"]["cget_results"] = {
                "study_uid": study_uid,
                "series_uid": series_uid,
                "files_retrieved": len(self._cget_received_files),
                "output_dir": str(output_dir),
            }

            # Security issue - bulk data retrieval
            if len(self._cget_received_files) > 0:
                self.logger.security_finding(
                    "Bulk image retrieval",
                    category=Category.ACCESS_CONTROL,
                    detail=f"Retrieved {len(self._cget_received_files)} images without additional auth",
                )

        except Exception as e:
            self.logger.debug("cget retrieve failed: %s", e)
            self.logger.fail(f"C-GET failed: {e}")

    def _cstore_send(self):
        """Upload DICOM files using C-STORE"""
        if not getattr(self.args, "confirm", False):
            self.logger.fail(
                "--store performs C-STORE upload (writes DICOM files into the PACS) "
                "— requires --confirm"
            )
            return
        if not self.assoc or not self.assoc.is_established:
            self.logger.fail("No active association for C-STORE")
            return

        store_file = getattr(self.args, "store_file", None)
        store_dir = getattr(self.args, "store_dir", None)

        if not store_file and not store_dir:
            self.logger.fail("C-STORE requires --store-file or --store-dir")
            return

        # Collect files to upload
        files_to_upload = []
        if store_file:
            files_to_upload.append(Path(store_file))
        if store_dir:
            store_path = Path(store_dir)
            files_to_upload.extend(store_path.glob("**/*.dcm"))

        if not files_to_upload:
            self.logger.fail("No DICOM files found to upload")
            return

        self.logger.display(f"Uploading {len(files_to_upload)} DICOM file(s)...")

        success_count = 0
        fail_count = 0

        for filepath in files_to_upload:
            try:
                # Read DICOM file
                ds = _get_dcmread()(str(filepath))

                # Send C-STORE
                status = self.assoc.send_c_store(ds)

                if status and status.Status == 0x0000:
                    success_count += 1
                    self.logger.success(f"  Uploaded: {filepath.name}")
                else:
                    fail_count += 1
                    if status:
                        self.logger.warning(
                            f"  Failed: {filepath.name} (status: 0x{status.Status:04X})"
                        )
                    else:
                        self.logger.warning(f"  Failed: {filepath.name} (status: None)")

            except Exception as e:
                self.logger.debug("cstore send failed: %s", e)
                fail_count += 1
                self.logger.fail(f"  Error uploading {filepath.name}: {e}")

        self.logger.display(f"C-STORE Results: {success_count} success, {fail_count} failed")

        self.results["data"]["cstore_results"] = {
            "files_uploaded": success_count,
            "files_failed": fail_count,
        }

        # Security issue - unrestricted upload
        if success_count > 0:
            self.logger.security_finding(
                "Unrestricted upload",
                category=Category.ACCESS_CONTROL,
                detail=f"Server accepted {success_count} file uploads from unknown source",
            )

    def _cmove_request(self):
        """Request image transfer using C-MOVE"""
        if not getattr(self.args, "confirm", False):
            self.logger.fail(
                "--move issues C-MOVE to --dest-aet (PHI exfiltration primitive) "
                "— requires --confirm"
            )
            return
        if not self.assoc or not self.assoc.is_established:
            self.logger.fail("No active association for C-MOVE")
            return

        study_uid = getattr(self.args, "study_uid", "")
        series_uid = getattr(self.args, "series_uid", "")
        dest_aet = getattr(self.args, "dest_aet", "")

        if not dest_aet:
            self.logger.fail("C-MOVE requires --dest-aet (destination AE Title)")
            return

        if not study_uid and not series_uid:
            self.logger.fail("C-MOVE requires --study-uid or --series-uid")
            return

        self.logger.display(f"Requesting transfer to AET: {dest_aet}...")

        # Create identifier dataset
        ds = _new_dataset()
        if series_uid:
            ds.QueryRetrieveLevel = "SERIES"
            ds.SeriesInstanceUID = series_uid
            if study_uid:
                ds.StudyInstanceUID = study_uid
        else:
            ds.QueryRetrieveLevel = "STUDY"
            ds.StudyInstanceUID = study_uid

        try:
            # StudyRoot Move: query is Study/Series-keyed with no PatientID, and
            # StudyRoot-only PACS reject PatientRoot (mirrors cfind.py).
            responses = self.assoc.send_c_move(
                ds,
                dest_aet,
                _sop("StudyRootQueryRetrieveInformationModelMove"),
            )

            completed = 0
            failed = 0
            warning = 0

            for status, identifier in responses:
                if status:
                    # Sub-operation counters may appear on Pending responses OR
                    # only on the terminal (Success/Warning) response, depending
                    # on the SCP. Capture them from whichever response carries
                    # them so a final-only SCP isn't reported as "0 transferred".
                    if hasattr(status, "NumberOfCompletedSuboperations"):
                        completed = status.NumberOfCompletedSuboperations
                    if hasattr(status, "NumberOfFailedSuboperations"):
                        failed = status.NumberOfFailedSuboperations
                    if hasattr(status, "NumberOfWarningSuboperations"):
                        warning = status.NumberOfWarningSuboperations

                    if status.Status in (0xFF00,):  # Pending
                        pass
                    elif status.Status == 0x0000:  # Success
                        self.logger.success(f"C-MOVE completed: {completed} transferred")
                    elif status.Status == 0xB000:  # Warning
                        self.logger.warning(
                            f"C-MOVE completed with warnings: {completed} transferred, {warning} warnings"
                        )
                    else:
                        self.logger.fail(f"C-MOVE failed: status 0x{status.Status:04X}")

            self.results["data"]["cmove_results"] = {
                "study_uid": study_uid,
                "series_uid": series_uid,
                "dest_aet": dest_aet,
                "completed": completed,
                "failed": failed,
            }

            # Security issue - open transfer
            if completed > 0:
                self.logger.security_finding(
                    "Open transfer",
                    category=Category.ACCESS_CONTROL,
                    detail=f"Server transferred {completed} images to external AET '{dest_aet}'",
                )

        except Exception as e:
            self.logger.debug("cmove request failed: %s", e)
            self.logger.fail(f"C-MOVE failed: {e}")
