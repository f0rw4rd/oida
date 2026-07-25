"""
DICOM C-FIND Mixin

Handles C-FIND query operations, result extraction, and display.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..cli_runner import PHI_TAGS, _new_dataset, _sop

if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


class CFindMixin(_ScannerBase):
    """Mixin providing C-FIND operations for the DICOM scanner."""

    def _cfind_query(self):
        """Perform C-FIND queries at PATIENT/STUDY/SERIES/IMAGE levels"""
        if not self.assoc or not self.assoc.is_established:
            self.logger.fail("No active association for C-FIND query")
            return

        query_level = getattr(self.args, "query_level", "PATIENT")
        # --patient-name is declared without default= in proto_args.py, so
        # argparse sets args.patient_name = None when the operator doesn't
        # pass it. getattr's default '*' was never used (the attribute
        # exists, just equals None). Result: queries went out with
        # PatientName=None instead of the wildcard, every documented
        # `oida dicom <host> --find` example failed or returned 0 rows.
        patient_name = getattr(self.args, "patient_name", "*") or "*"
        patient_id = getattr(self.args, "patient_id", "")
        study_date = getattr(self.args, "study_date", "")
        study_uid = getattr(self.args, "study_uid", "")
        series_uid = getattr(self.args, "series_uid", "")
        modality = getattr(self.args, "modality", "")
        accession_number = getattr(self.args, "accession_number", "")
        max_results = getattr(self.args, "max_results", 100)
        extract_metadata = getattr(self.args, "metadata", False)

        self.logger.display(f"Performing C-FIND at {query_level} level...")

        # Create query dataset based on level
        ds = _new_dataset()
        ds.QueryRetrieveLevel = query_level

        results = []
        try:
            if query_level == "PATIENT":
                ds.PatientName = patient_name
                # Return keys
                ds.PatientID = patient_id or ""
                ds.PatientBirthDate = ""
                ds.PatientSex = ""
                ds.NumberOfPatientRelatedStudies = ""

            elif query_level == "STUDY":
                # ModalitiesInStudy is study-level only (no return key below)
                if modality:
                    ds.ModalitiesInStudy = modality
                # Return keys (also carry the query filters when supplied)
                ds.StudyInstanceUID = ""
                ds.StudyDate = study_date or ""
                ds.StudyTime = ""
                ds.StudyDescription = ""
                ds.AccessionNumber = accession_number or ""
                ds.PatientName = patient_name or ""
                ds.PatientID = patient_id or ""
                ds.NumberOfStudyRelatedSeries = ""

            elif query_level == "SERIES":
                if not study_uid:
                    self.logger.fail("SERIES level query requires --study-uid")
                    return
                ds.StudyInstanceUID = study_uid
                # Return keys
                ds.SeriesInstanceUID = ""
                ds.SeriesNumber = ""
                ds.SeriesDescription = ""
                ds.Modality = modality or ""
                ds.NumberOfSeriesRelatedInstances = ""

            elif query_level == "IMAGE":
                if not series_uid:
                    self.logger.fail("IMAGE level query requires --series-uid")
                    return
                ds.SeriesInstanceUID = series_uid
                if study_uid:
                    ds.StudyInstanceUID = study_uid
                # Return keys
                ds.SOPInstanceUID = ""
                ds.InstanceNumber = ""
                ds.SOPClassUID = ""

            # PatientRootQueryRetrieveInformationModel is the only model that
            # supports the PATIENT level; StudyRoot doesn't. But many
            # StudyRoot-only PACS archives don't accept PatientRoot at all, so
            # hard-coding PatientRoot for STUDY/SERIES/IMAGE queries against
            # such a server means the presentation context was never accepted
            # and send_c_find() returns 0 rows. Match the model enumeration.py
            # already uses for its own STUDY-level queries.
            model = _sop(
                "PatientRootQueryRetrieveInformationModelFind"
                if query_level == "PATIENT"
                else "StudyRootQueryRetrieveInformationModelFind"
            )
            responses = self.assoc.send_c_find(ds, model)

            for status, identifier in responses:
                if status and status.Status in (0xFF00, 0xFF01):  # Pending
                    if identifier:
                        result = self._extract_cfind_result(
                            identifier, query_level, extract_metadata
                        )
                        results.append(result)

                        if len(results) <= 10:  # Show first 10
                            self._display_cfind_result(result, query_level)

                        if len(results) >= max_results:
                            self.logger.warning(f"Reached max results limit ({max_results})")
                            break

            self.logger.display(f"C-FIND Results: {len(results)} {query_level.lower()}s found")

            # NOTE: the "Unrestricted query access" wildcard finding is emitted
            # once by _analyze_security() (reporting.py) from cfind_results, so
            # it is intentionally NOT emitted inline here to avoid double-report.

        except Exception as e:
            self.logger.debug("cfind query failed: %s", e)
            self.logger.fail(f"C-FIND failed: {e}")

        self.results["data"]["cfind_results"] = {
            "query_level": query_level,
            "query": {"PatientName": patient_name},
            "count": len(results),
            "results": results[:50],  # Store first 50 for export
        }

    def _extract_cfind_result(
        self, identifier, query_level: str, extract_metadata: bool = False
    ) -> dict:
        """Extract fields from C-FIND result based on query level"""
        result = {}

        # Check for full tag dump mode
        dump_tags = getattr(self.args, "dump_tags", False)
        phi_only = getattr(self.args, "phi_only", False)

        if dump_tags:
            # Extract ALL DICOM tags from the dataset
            result = self._extract_all_tags(identifier, phi_only)
            return result

        if query_level == "PATIENT":
            result = {
                "PatientName": str(getattr(identifier, "PatientName", "")),
                "PatientID": str(getattr(identifier, "PatientID", "")),
                "PatientBirthDate": str(getattr(identifier, "PatientBirthDate", "")),
                "PatientSex": str(getattr(identifier, "PatientSex", "")),
                "StudyCount": str(getattr(identifier, "NumberOfPatientRelatedStudies", "")),
            }
        elif query_level == "STUDY":
            result = {
                "StudyInstanceUID": str(getattr(identifier, "StudyInstanceUID", "")),
                "StudyDate": str(getattr(identifier, "StudyDate", "")),
                "StudyTime": str(getattr(identifier, "StudyTime", "")),
                "StudyDescription": str(getattr(identifier, "StudyDescription", "")),
                "AccessionNumber": str(getattr(identifier, "AccessionNumber", "")),
                "PatientName": str(getattr(identifier, "PatientName", "")),
                "PatientID": str(getattr(identifier, "PatientID", "")),
                "SeriesCount": str(getattr(identifier, "NumberOfStudyRelatedSeries", "")),
            }
        elif query_level == "SERIES":
            result = {
                "SeriesInstanceUID": str(getattr(identifier, "SeriesInstanceUID", "")),
                "SeriesNumber": str(getattr(identifier, "SeriesNumber", "")),
                "SeriesDescription": str(getattr(identifier, "SeriesDescription", "")),
                "Modality": str(getattr(identifier, "Modality", "")),
                "InstanceCount": str(getattr(identifier, "NumberOfSeriesRelatedInstances", "")),
            }
        elif query_level == "IMAGE":
            result = {
                "SOPInstanceUID": str(getattr(identifier, "SOPInstanceUID", "")),
                "InstanceNumber": str(getattr(identifier, "InstanceNumber", "")),
                "SOPClassUID": str(getattr(identifier, "SOPClassUID", "")),
            }

        # Extract additional metadata fields if requested
        if extract_metadata:
            extract_fields = getattr(self.args, "extract_fields", "")
            if extract_fields:
                for field in extract_fields.split(","):
                    field = field.strip()
                    if hasattr(identifier, field):
                        result[field] = str(getattr(identifier, field, ""))

        return result

    # Hardening guards against a hostile DICOM responder returning deeply or
    # pathologically nested C-FIND identifiers (see threat model). Bounds the
    # recursion depth and total element count so --dump-tags extraction cannot
    # be driven into RecursionError / stack exhaustion.
    _MAX_TAG_DEPTH = 32
    _MAX_TAG_ELEMENTS = 100000

    def _extract_all_tags(
        self, dataset, phi_only: bool = False, _depth: int = 0, _counter: list | None = None
    ) -> dict:
        """
        Extract all DICOM tags from a dataset.

        Args:
            dataset: pydicom Dataset object
            phi_only: If True, only extract PHI-containing tags
            _depth: Current sequence-nesting depth (internal recursion guard)
            _counter: Single-element list tracking total elements extracted
                across the whole tree (internal recursion guard)

        Returns:
            Dictionary of tag_name -> value mappings
        """
        result = {}

        if dataset is None:
            return result

        if _counter is None:
            _counter = [0]

        # Guard against attacker-controlled deeply nested sequences driving
        # Python recursion into stack exhaustion.
        if _depth > self._MAX_TAG_DEPTH:
            result["_extraction_error"] = f"max nesting depth ({self._MAX_TAG_DEPTH}) exceeded"
            return result

        try:
            for elem in dataset:
                # Guard against an oversized identifier exhausting memory/time.
                if _counter[0] >= self._MAX_TAG_ELEMENTS:
                    result["_extraction_error"] = (
                        f"max element count ({self._MAX_TAG_ELEMENTS}) exceeded"
                    )
                    break
                _counter[0] += 1

                # Recursively extract sequence (nested dataset) items
                if elem.VR == "SQ":
                    # Recursively extract from sequence items
                    if elem.value:
                        seq_items = []
                        for item in elem.value:
                            seq_items.append(
                                self._extract_all_tags(item, phi_only, _depth + 1, _counter)
                            )
                        if seq_items:
                            result[elem.keyword or f"Tag_{elem.tag}"] = seq_items
                    continue

                # Get tag name (keyword) or use tag number if unknown
                tag_name = (
                    elem.keyword
                    if elem.keyword
                    else f"({elem.tag.group:04X},{elem.tag.element:04X})"
                )

                # Check if this is a private tag (odd group number)
                is_private = elem.tag.is_private

                # Filter PHI tags if requested
                if phi_only:
                    if tag_name not in PHI_TAGS and not is_private:
                        continue

                # Extract value
                try:
                    if elem.VR in ("OB", "OW", "OF", "OD", "UN"):
                        # Binary data - just note its presence
                        result[tag_name] = (
                            f"<binary data: {len(elem.value) if elem.value else 0} bytes>"
                        )
                    elif elem.VR == "PN":
                        # Person name - convert to string
                        result[tag_name] = str(elem.value) if elem.value else ""
                    else:
                        # Regular value
                        value = elem.value
                        if value is None:
                            result[tag_name] = ""
                        elif isinstance(value, (list, tuple)):
                            result[tag_name] = [str(v) for v in value]
                        else:
                            result[tag_name] = str(value)

                    # Mark private tags
                    if is_private:
                        result[f"{tag_name}_PRIVATE"] = True

                except Exception as e:
                    self.logger.debug("extract all tags failed: %s", e)
                    result[tag_name] = f"<error extracting: {e}>"

        except Exception as e:
            self.logger.debug("extract all tags failed: %s", e)
            result["_extraction_error"] = str(e)

        return result

    def _display_cfind_result(self, result: dict, query_level: str):
        """Display C-FIND result based on query level"""
        # Check for tag dump mode
        dump_tags = getattr(self.args, "dump_tags", False)
        phi_only = getattr(self.args, "phi_only", False)

        if dump_tags:
            # Display all extracted tags
            phi_count = 0
            for tag_name, value in result.items():
                if tag_name.endswith("_PRIVATE"):
                    continue  # Skip private marker flags
                is_phi = tag_name in PHI_TAGS
                if is_phi:
                    phi_count += 1
                    self.logger.warning(f"  PHI: {tag_name}: {value}")
                elif tag_name.startswith("("):
                    # Private/unknown tag
                    self.logger.display(f"  Private: {tag_name}: {value}")
                else:
                    self.logger.display(f"  {tag_name}: {value}")
            if phi_only:
                self.logger.display(f"  --- {phi_count} PHI tags found ---")
            return

        if query_level == "PATIENT":
            self.logger.display(
                f"  Patient: {result.get('PatientName', '')} (ID: {result.get('PatientID', '')})"
            )
        elif query_level == "STUDY":
            self.logger.display(
                f"  Study: {result.get('StudyDate', '')} - {result.get('StudyDescription', '')} (UID: {result.get('StudyInstanceUID', '')[:30]}...)"
            )
        elif query_level == "SERIES":
            self.logger.display(
                f"  Series: {result.get('Modality', '')} #{result.get('SeriesNumber', '')} - {result.get('SeriesDescription', '')} ({result.get('InstanceCount', '')} images)"
            )
        elif query_level == "IMAGE":
            self.logger.display(
                f"  Image: #{result.get('InstanceNumber', '')} (UID: {result.get('SOPInstanceUID', '')[:30]}...)"
            )
