#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Behavioral unit tests for the DICOM enumeration and operations mixins.

Covers:
- EnumerationMixin._enum_operators / _enum_devices / _time_analysis
- OperationsMixin._recursive_bulk_export / _cget_retrieve / _cstore_send / _cmove_request

The only mocked boundary is the pynetdicom *association* object (the DIMSE
service: send_c_find / send_c_get / send_c_move / send_c_store). The mixin
parsing/aggregation logic itself runs unmodified and is asserted against the
emitted findings, the populated ``results["data"]`` blocks, and the C-FIND
identifier datasets the SCU sends. Identifiers are built from REAL pydicom
``Dataset`` objects so ``getattr(identifier, ...)`` exercises the production
attribute-access path.
"""

import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import Mock

from tests.service_gate import require_import

require_import(
    "pynetdicom", reason="pynetdicom not installed; install via `pip install -e .[dicom]`"
)
from pydicom.dataset import Dataset

# Reuse the construction helper / fixtures from the sibling scanner suite so the
# NXC object is built WITHOUT triggering proto_flow (no real socket opened).
from tests.unit.dicom.test_scanner import _make_dicom_instance


# ---------------------------------------------------------------------------
# Realistic C-FIND/C-GET/C-MOVE/C-STORE association fakes
# ---------------------------------------------------------------------------
def _status(code):
    """Build a DIMSE status object with a .Status attribute."""
    s = Mock()
    s.Status = code
    return s


def _ds(**fields) -> "Dataset":
    """Build a real pydicom identifier Dataset from keyword fields."""
    d = Dataset()
    for k, v in fields.items():
        setattr(d, k, v)
    return d


def _pending_responses(identifiers):
    """Yield (pending, identifier) tuples then a terminal success/None."""
    out = [(_status(0xFF00), ident) for ident in identifiers]
    out.append((_status(0x0000), None))
    return out


class ScriptedFindAssoc:
    """Association whose send_c_find replays scripted identifier datasets.

    ``find_script`` maps QueryRetrieveLevel -> list of identifier Datasets.
    Every C-FIND call is recorded in ``find_calls`` as (level, identifier_ds).
    """

    def __init__(self, find_script=None, established=True):
        self.is_established = established
        self.find_script = find_script or {}
        self.find_calls = []

    def send_c_find(self, dataset, model):
        level = str(getattr(dataset, "QueryRetrieveLevel", ""))
        self.find_calls.append((level, dataset))
        return iter(_pending_responses(self.find_script.get(level, [])))

    def release(self):
        self.is_established = False


# ---------------------------------------------------------------------------
# Shared minimal args
# ---------------------------------------------------------------------------
def _args(**overrides):
    a = Mock()
    a.port = 11112
    a.timeout = 5
    a.aet = "OIDA"
    a.called_aet = "ANY"
    a.tls = False
    a.confirm = False
    for k, v in overrides.items():
        setattr(a, k, v)
    return a


def _finding_titles(scanner):
    titles = []
    for call in scanner.logger.security_finding.call_args_list:
        if call.args:
            titles.append(str(call.args[0]))
        elif "title" in call.kwargs:
            titles.append(str(call.kwargs["title"]))
    return titles


def _finding_categories(scanner):
    return [call.kwargs.get("category") for call in scanner.logger.security_finding.call_args_list]


# ===========================================================================
# EnumerationMixin._enum_operators
# ===========================================================================
class TestEnumOperators(unittest.TestCase):
    def test_parses_and_dedupes_personnel(self):
        """Personnel fields are extracted, deduplicated and stored."""
        studies = [
            _ds(
                QueryRetrieveLevel="STUDY",
                StudyInstanceUID="1.2.1",
                OperatorsName="TECH^ALICE",
                PerformingPhysicianName="DR^HOUSE",
                ReferringPhysicianName="DR^WILSON",
                NameOfPhysiciansReadingStudy="DR^RADIO",
                RequestingPhysician="DR^ORDER",
                InstitutionName="MERCY",
            ),
            # Duplicate operator + new performing physician -> dedupe one, add one
            _ds(
                QueryRetrieveLevel="STUDY",
                StudyInstanceUID="1.2.2",
                OperatorsName="TECH^ALICE",
                PerformingPhysicianName="DR^CUDDY",
            ),
        ]
        scanner = _make_dicom_instance(_args())
        scanner.logger = Mock()
        scanner.assoc = ScriptedFindAssoc({"STUDY": studies})

        scanner._enum_operators()

        personnel = scanner.results["data"]["personnel"]
        self.assertEqual(personnel["operators"], ["TECH^ALICE"])  # deduped
        self.assertEqual(personnel["performing_physicians"], ["DR^CUDDY", "DR^HOUSE"])  # sorted
        self.assertEqual(personnel["referring_physicians"], ["DR^WILSON"])
        self.assertEqual(personnel["reading_physicians"], ["DR^RADIO"])
        self.assertEqual(personnel["requesting_physicians"], ["DR^ORDER"])
        self.assertEqual(personnel["studies_scanned"], 2)

        # The SCU must have queried at STUDY level with a wildcard PatientName.
        level, ident = scanner.assoc.find_calls[0]
        self.assertEqual(level, "STUDY")
        self.assertEqual(str(getattr(ident, "PatientName", "")), "*")

    def test_no_personnel_warns_and_stores_empty(self):
        """Studies without personnel fields warn and store empty lists."""
        studies = [_ds(QueryRetrieveLevel="STUDY", StudyInstanceUID="1.2.3", StudyDate="20240101")]
        scanner = _make_dicom_instance(_args())
        scanner.logger = Mock()
        scanner.assoc = ScriptedFindAssoc({"STUDY": studies})

        scanner._enum_operators()

        personnel = scanner.results["data"]["personnel"]
        self.assertEqual(personnel["operators"], [])
        self.assertEqual(personnel["studies_scanned"], 1)
        warn_text = " ".join(
            str(c.args[0]) for c in scanner.logger.warning.call_args_list if c.args
        )
        self.assertIn("No personnel", warn_text)

    def test_study_limit_breaks_and_warns(self):
        """More than max_studies (500) pending studies stops at the cap."""
        studies = [
            _ds(QueryRetrieveLevel="STUDY", StudyInstanceUID=f"1.2.{i}", OperatorsName=f"OP{i}")
            for i in range(510)
        ]
        scanner = _make_dicom_instance(_args())
        scanner.logger = Mock()
        scanner.assoc = ScriptedFindAssoc({"STUDY": studies})

        scanner._enum_operators()

        self.assertEqual(scanner.results["data"]["personnel"]["studies_scanned"], 500)
        warn_text = " ".join(
            str(c.args[0]) for c in scanner.logger.warning.call_args_list if c.args
        )
        self.assertIn("study limit", warn_text)

    def test_no_association_fails_cleanly(self):
        scanner = _make_dicom_instance(_args())
        scanner.logger = Mock()
        scanner.assoc = None

        scanner._enum_operators()

        self.assertNotIn("personnel", scanner.results["data"])
        fail_text = " ".join(str(c.args[0]) for c in scanner.logger.fail.call_args_list if c.args)
        self.assertIn("No active association", fail_text)

    def test_send_c_find_exception_is_caught(self):
        """A DIMSE failure mid-query is reported via fail(), not raised."""
        scanner = _make_dicom_instance(_args())
        scanner.logger = Mock()
        assoc = Mock()
        assoc.is_established = True
        assoc.send_c_find.side_effect = RuntimeError("association aborted")
        scanner.assoc = assoc

        scanner._enum_operators()  # must not raise

        fail_text = " ".join(str(c.args[0]) for c in scanner.logger.fail.call_args_list if c.args)
        self.assertIn("Operator enumeration failed", fail_text)


# ===========================================================================
# EnumerationMixin._enum_devices
# ===========================================================================
class TestEnumDevices(unittest.TestCase):
    def test_flat_series_query_collects_device_info(self):
        """Lenient SCP answers the flat SERIES query in one shot."""
        series = [
            _ds(
                QueryRetrieveLevel="SERIES",
                SeriesInstanceUID="1.3.1",
                Modality="CT",
                StationName="CT-SCANNER-01",
                Manufacturer="GE MEDICAL SYSTEMS",
                ManufacturerModelName="Revolution",
                InstitutionName="MERCY",
            ),
            _ds(
                QueryRetrieveLevel="SERIES",
                SeriesInstanceUID="1.3.2",
                Modality="MR",
                StationName="MR-01",
                Manufacturer="SIEMENS",
            ),
        ]
        scanner = _make_dicom_instance(_args())
        scanner.logger = Mock()
        scanner.assoc = ScriptedFindAssoc({"SERIES": series})

        scanner._enum_devices()

        devices = scanner.results["data"]["devices"]
        self.assertEqual(devices["modalities"], ["CT", "MR"])
        self.assertEqual(devices["stations"], ["CT-SCANNER-01", "MR-01"])
        self.assertEqual(devices["manufacturers"], ["GE MEDICAL SYSTEMS", "SIEMENS"])
        self.assertEqual(devices["models"], ["Revolution"])
        self.assertEqual(devices["institutions"], ["MERCY"])
        self.assertEqual(devices["series_scanned"], 2)
        # No study-by-study fallback should have been needed.
        self.assertEqual([lvl for lvl, _ in scanner.assoc.find_calls], ["SERIES"])

    def test_strict_scp_triggers_study_by_study_fallback(self):
        """Strict Study-Root SCP returns nothing for a flat SERIES query, so the
        mixin must enumerate studies then re-query SERIES per StudyInstanceUID."""

        class StrictAssoc:
            def __init__(self):
                self.is_established = True
                self.calls = []

            def send_c_find(self, dataset, model):
                level = str(getattr(dataset, "QueryRetrieveLevel", ""))
                study_uid = str(getattr(dataset, "StudyInstanceUID", ""))
                self.calls.append((level, study_uid))
                if level == "SERIES" and study_uid == "":
                    # strict SCP: flat series query yields nothing
                    return iter(_pending_responses([]))
                if level == "STUDY":
                    return iter(
                        _pending_responses(
                            [
                                _ds(QueryRetrieveLevel="STUDY", StudyInstanceUID="S1"),
                                _ds(QueryRetrieveLevel="STUDY", StudyInstanceUID="S2"),
                            ]
                        )
                    )
                # SERIES query scoped to a real study UID
                return iter(
                    _pending_responses(
                        [_ds(QueryRetrieveLevel="SERIES", SeriesInstanceUID="X", Modality="US")]
                    )
                )

        scanner = _make_dicom_instance(_args())
        scanner.logger = Mock()
        scanner.assoc = StrictAssoc()

        scanner._enum_devices()

        devices = scanner.results["data"]["devices"]
        self.assertEqual(devices["modalities"], ["US"])
        self.assertEqual(devices["series_scanned"], 2)  # one series per study UID
        # Verify the fallback descended per-study: flat SERIES, STUDY enum, then
        # one scoped SERIES query per discovered study UID.
        self.assertIn(("SERIES", ""), scanner.assoc.calls)
        self.assertIn(("STUDY", ""), scanner.assoc.calls)
        self.assertIn(("SERIES", "S1"), scanner.assoc.calls)
        self.assertIn(("SERIES", "S2"), scanner.assoc.calls)

    def test_no_devices_warns_and_skips_store(self):
        """Empty results warn and leave devices block unset (early return)."""
        scanner = _make_dicom_instance(_args())
        scanner.logger = Mock()
        scanner.assoc = ScriptedFindAssoc({"SERIES": [], "STUDY": []})

        scanner._enum_devices()

        self.assertNotIn("devices", scanner.results["data"])
        warn_text = " ".join(
            str(c.args[0]) for c in scanner.logger.warning.call_args_list if c.args
        )
        self.assertIn("No device information", warn_text)

    def test_no_association_fails(self):
        scanner = _make_dicom_instance(_args())
        scanner.logger = Mock()
        scanner.assoc = None
        scanner._enum_devices()
        fail_text = " ".join(str(c.args[0]) for c in scanner.logger.fail.call_args_list if c.args)
        self.assertIn("No active association", fail_text)

    def test_send_c_find_exception_caught(self):
        scanner = _make_dicom_instance(_args())
        scanner.logger = Mock()
        assoc = Mock()
        assoc.is_established = True
        assoc.send_c_find.side_effect = OSError("connection reset")
        scanner.assoc = assoc
        scanner._enum_devices()
        fail_text = " ".join(str(c.args[0]) for c in scanner.logger.fail.call_args_list if c.args)
        self.assertIn("Device enumeration failed", fail_text)


# ===========================================================================
# EnumerationMixin._time_analysis
# ===========================================================================
class TestTimeAnalysis(unittest.TestCase):
    def _run_with_dates(self, study_dates):
        studies = [
            _ds(QueryRetrieveLevel="STUDY", StudyInstanceUID=f"1.{i}", StudyDate=d, Modality="CT")
            for i, d in enumerate(study_dates)
        ]
        scanner = _make_dicom_instance(_args())
        scanner.logger = Mock()
        scanner.assoc = ScriptedFindAssoc({"STUDY": studies})
        scanner._time_analysis()
        return scanner

    def test_computes_retention_window_and_distribution(self):
        scanner = self._run_with_dates(["20180115", "20190620", "20240301"])
        ta = scanner.results["data"]["time_analysis"]
        self.assertEqual(ta["oldest_study"], "2018-01-15")
        self.assertEqual(ta["newest_study"], "2024-03-01")
        self.assertEqual(ta["studies_analyzed"], 3)
        self.assertEqual(ta["years"], {"2018": 1, "2019": 1, "2024": 1})
        self.assertIn("201801", ta["recent_months"])
        # retention spans ~6 years
        self.assertGreater(ta["retention_days"], 365 * 5)

    def test_extended_retention_emits_critical_fail(self):
        """>10 years of historical PHI must hit the CRITICAL fail branch."""
        scanner = self._run_with_dates(["20050101", "20240101"])
        ta = scanner.results["data"]["time_analysis"]
        self.assertGreater(ta["retention_days"], 365 * 10)
        fail_text = " ".join(str(c.args[0]) for c in scanner.logger.fail.call_args_list if c.args)
        self.assertIn("CRITICAL", fail_text)
        self.assertIn("years of historical PHI", fail_text)

    def test_recent_study_flagged_active(self):
        """A study within 30 days flags the system as active."""
        recent = (datetime.now() - timedelta(days=5)).strftime("%Y%m%d")
        scanner = self._run_with_dates(["20200101", recent])
        warn_text = " ".join(
            str(c.args[0]) for c in scanner.logger.warning.call_args_list if c.args
        )
        self.assertIn("Active system", warn_text)

    def test_malformed_dates_skipped(self):
        """Non-parseable / short StudyDate values are ignored, not fatal."""
        scanner = self._run_with_dates(["BADDATE!", "2024", "20240301"])
        ta = scanner.results["data"]["time_analysis"]
        # Only the one valid 8-char date survives; studies_analyzed still counts all 3 pending.
        self.assertEqual(ta["oldest_study"], "2024-03-01")
        self.assertEqual(ta["newest_study"], "2024-03-01")
        self.assertEqual(ta["studies_analyzed"], 3)

    def test_no_valid_dates_warns_and_returns(self):
        scanner = self._run_with_dates(["", "BAD"])
        self.assertNotIn("time_analysis", scanner.results["data"])
        warn_text = " ".join(
            str(c.args[0]) for c in scanner.logger.warning.call_args_list if c.args
        )
        self.assertIn("No valid study dates", warn_text)

    def test_no_association_fails(self):
        scanner = _make_dicom_instance(_args())
        scanner.logger = Mock()
        scanner.assoc = None
        scanner._time_analysis()
        fail_text = " ".join(str(c.args[0]) for c in scanner.logger.fail.call_args_list if c.args)
        self.assertIn("No active association", fail_text)

    def test_send_c_find_exception_caught(self):
        scanner = _make_dicom_instance(_args())
        scanner.logger = Mock()
        assoc = Mock()
        assoc.is_established = True
        assoc.send_c_find.side_effect = RuntimeError("boom")
        scanner.assoc = assoc
        scanner._time_analysis()
        fail_text = " ".join(str(c.args[0]) for c in scanner.logger.fail.call_args_list if c.args)
        self.assertIn("Time analysis failed", fail_text)


# ===========================================================================
# OperationsMixin._recursive_bulk_export
# ===========================================================================
class BulkExportAssoc:
    """Three-level C-FIND tree + a C-GET that 'receives' images by appending
    to the scanner's _cget_received_files list (mimicking the bound C-STORE
    handler) so the bulk-export image counter is exercised end to end."""

    def __init__(self, scanner, patients, studies_by_patient, series_by_study, images_per_series=2):
        self.scanner = scanner
        self.is_established = True
        self.patients = patients
        self.studies_by_patient = studies_by_patient
        self.series_by_study = series_by_study
        self.images_per_series = images_per_series
        self.get_calls = []

    def send_c_find(self, dataset, model):
        level = str(getattr(dataset, "QueryRetrieveLevel", ""))
        if level == "PATIENT":
            return iter(_pending_responses(self.patients))
        if level == "STUDY":
            pid = str(getattr(dataset, "PatientID", ""))
            return iter(_pending_responses(self.studies_by_patient.get(pid, [])))
        if level == "SERIES":
            suid = str(getattr(dataset, "StudyInstanceUID", ""))
            return iter(_pending_responses(self.series_by_study.get(suid, [])))
        return iter(_pending_responses([]))

    def send_c_get(self, dataset, model):
        self.get_calls.append(str(getattr(dataset, "SeriesInstanceUID", "")))
        # Simulate the bound C-STORE handler writing images for this series.
        for _ in range(self.images_per_series):
            self.scanner._cget_received_files.append("img.dcm")
        return iter([(_status(0x0000), None)])


class TestRecursiveBulkExport(unittest.TestCase):
    def test_full_tree_export_counts_and_finding(self):
        with tempfile.TemporaryDirectory() as tmp:
            scanner = _make_dicom_instance(_args(output_dir=tmp, max_patients=10, max_studies=50))
            scanner.logger = Mock()

            patients = [
                _ds(QueryRetrieveLevel="PATIENT", PatientID="P1", PatientName="A^A"),
                _ds(QueryRetrieveLevel="PATIENT", PatientID="P2", PatientName="B^B"),
            ]
            studies = {
                "P1": [
                    _ds(QueryRetrieveLevel="STUDY", StudyInstanceUID="S1", StudyDate="20240101")
                ],
                "P2": [
                    _ds(QueryRetrieveLevel="STUDY", StudyInstanceUID="S2", StudyDate="20240102")
                ],
            }
            series = {
                "S1": [_ds(QueryRetrieveLevel="SERIES", SeriesInstanceUID="SE1", Modality="CT")],
                "S2": [_ds(QueryRetrieveLevel="SERIES", SeriesInstanceUID="SE2", Modality="MR")],
            }
            scanner.assoc = BulkExportAssoc(scanner, patients, studies, series, images_per_series=3)

            scanner._recursive_bulk_export()

            stats = scanner.results["data"]["bulk_export"]
            self.assertEqual(stats["patients"], 2)
            self.assertEqual(stats["studies"], 2)
            self.assertEqual(stats["series"], 2)
            self.assertEqual(stats["images"], 6)  # 2 series * 3 images each

            # C-GET issued once per series.
            self.assertEqual(sorted(scanner.assoc.get_calls), ["SE1", "SE2"])

            titles = _finding_titles(scanner)
            self.assertIn("Mass data exfiltration", titles)

    def test_max_patients_cap_respected(self):
        with tempfile.TemporaryDirectory() as tmp:
            scanner = _make_dicom_instance(_args(output_dir=tmp, max_patients=1, max_studies=50))
            scanner.logger = Mock()
            patients = [
                _ds(QueryRetrieveLevel="PATIENT", PatientID=f"P{i}", PatientName="X^Y")
                for i in range(5)
            ]
            studies = {
                "P0": [_ds(QueryRetrieveLevel="STUDY", StudyInstanceUID="S0")],
            }
            series = {"S0": []}
            scanner.assoc = BulkExportAssoc(scanner, patients, studies, series)

            scanner._recursive_bulk_export()

            self.assertEqual(scanner.results["data"]["bulk_export"]["patients"], 1)

    def test_no_images_emits_no_finding(self):
        with tempfile.TemporaryDirectory() as tmp:
            scanner = _make_dicom_instance(_args(output_dir=tmp, max_patients=10, max_studies=50))
            scanner.logger = Mock()
            patients = [_ds(QueryRetrieveLevel="PATIENT", PatientID="P1", PatientName="A^A")]
            studies = {"P1": [_ds(QueryRetrieveLevel="STUDY", StudyInstanceUID="S1")]}
            series = {"S1": [_ds(QueryRetrieveLevel="SERIES", SeriesInstanceUID="SE1")]}
            scanner.assoc = BulkExportAssoc(scanner, patients, studies, series, images_per_series=0)

            scanner._recursive_bulk_export()

            self.assertEqual(scanner.results["data"]["bulk_export"]["images"], 0)
            self.assertNotIn("Mass data exfiltration", _finding_titles(scanner))

    def test_patient_enum_exception_aborts(self):
        with tempfile.TemporaryDirectory() as tmp:
            scanner = _make_dicom_instance(_args(output_dir=tmp))
            scanner.logger = Mock()
            assoc = Mock()
            assoc.is_established = True
            assoc.send_c_find.side_effect = RuntimeError("aborted")
            scanner.assoc = assoc

            scanner._recursive_bulk_export()

            self.assertNotIn("bulk_export", scanner.results["data"])
            fail_text = " ".join(
                str(c.args[0]) for c in scanner.logger.fail.call_args_list if c.args
            )
            self.assertIn("Patient enumeration failed", fail_text)

    def test_no_association_fails(self):
        scanner = _make_dicom_instance(_args(output_dir="/tmp/x"))
        scanner.logger = Mock()
        scanner.assoc = None
        scanner._recursive_bulk_export()
        fail_text = " ".join(str(c.args[0]) for c in scanner.logger.fail.call_args_list if c.args)
        self.assertIn("No active association", fail_text)

    def test_per_patient_study_cap_and_inner_exceptions(self):
        """max_studies caps studies per patient; study/series/get level exceptions
        are caught per-iteration without aborting the whole export."""
        with tempfile.TemporaryDirectory() as tmp:
            scanner = _make_dicom_instance(_args(output_dir=tmp, max_patients=10, max_studies=1))
            scanner.logger = Mock()

            class FlakyAssoc:
                def __init__(self, scanner):
                    self.scanner = scanner
                    self.is_established = True

                def send_c_find(self, dataset, model):
                    level = str(getattr(dataset, "QueryRetrieveLevel", ""))
                    if level == "PATIENT":
                        return iter(
                            _pending_responses(
                                [
                                    _ds(
                                        QueryRetrieveLevel="PATIENT",
                                        PatientID="P1",
                                        PatientName="A",
                                    ),
                                    _ds(
                                        QueryRetrieveLevel="PATIENT",
                                        PatientID="P2",
                                        PatientName="B",
                                    ),
                                ]
                            )
                        )
                    if level == "STUDY":
                        pid = str(getattr(dataset, "PatientID", ""))
                        if pid == "P2":
                            raise RuntimeError("study enum boom")  # caught, logged debug
                        # P1: return TWO studies but max_studies=1 caps to one
                        return iter(
                            _pending_responses(
                                [
                                    _ds(QueryRetrieveLevel="STUDY", StudyInstanceUID="S1"),
                                    _ds(QueryRetrieveLevel="STUDY", StudyInstanceUID="S1b"),
                                ]
                            )
                        )
                    if level == "SERIES":
                        raise RuntimeError("series enum boom")  # caught per-study
                    return iter(_pending_responses([]))

                def send_c_get(self, dataset, model):  # pragma: no cover - no series reach here
                    raise RuntimeError("get boom")

            scanner.assoc = FlakyAssoc(scanner)

            scanner._recursive_bulk_export()  # must not raise

            stats = scanner.results["data"]["bulk_export"]
            self.assertEqual(stats["patients"], 2)
            self.assertEqual(stats["studies"], 1)  # P1 capped at 1, P2 raised
            self.assertEqual(stats["series"], 0)  # series enum always raised
            self.assertEqual(stats["images"], 0)

    def test_cget_level_exception_caught(self):
        """A C-GET failure on one series is swallowed; export still completes."""
        with tempfile.TemporaryDirectory() as tmp:
            scanner = _make_dicom_instance(_args(output_dir=tmp, max_patients=10, max_studies=50))
            scanner.logger = Mock()

            class GetFailAssoc(BulkExportAssoc):
                def send_c_get(self, dataset, model):
                    raise RuntimeError("c-get reset")

            patients = [_ds(QueryRetrieveLevel="PATIENT", PatientID="P1", PatientName="A")]
            studies = {"P1": [_ds(QueryRetrieveLevel="STUDY", StudyInstanceUID="S1")]}
            series = {"S1": [_ds(QueryRetrieveLevel="SERIES", SeriesInstanceUID="SE1")]}
            scanner.assoc = GetFailAssoc(scanner, patients, studies, series)

            scanner._recursive_bulk_export()  # must not raise

            self.assertEqual(scanner.results["data"]["bulk_export"]["series"], 1)
            self.assertEqual(scanner.results["data"]["bulk_export"]["images"], 0)


# ===========================================================================
# OperationsMixin._cget_retrieve
# ===========================================================================
class CGetAssoc:
    def __init__(self, scanner, files, statuses=None):
        self.scanner = scanner
        self.is_established = True
        self.files = files
        self.statuses = statuses or [0x0000]
        self.last_dataset = None

    def send_c_get(self, dataset, model):
        self.last_dataset = dataset
        for _ in range(self.files):
            self.scanner._cget_received_files.append("img.dcm")
        return iter([(_status(s), None) for s in self.statuses])


class TestCGetRetrieve(unittest.TestCase):
    def test_series_level_retrieval_and_finding(self):
        with tempfile.TemporaryDirectory() as tmp:
            scanner = _make_dicom_instance(
                _args(study_uid="1.2.STUDY", series_uid="1.2.SERIES", output_dir=tmp)
            )
            scanner.logger = Mock()
            scanner.assoc = CGetAssoc(scanner, files=4)

            scanner._cget_retrieve()

            res = scanner.results["data"]["cget_results"]
            self.assertEqual(res["files_retrieved"], 4)
            self.assertEqual(res["series_uid"], "1.2.SERIES")
            self.assertEqual(res["study_uid"], "1.2.STUDY")

            # SERIES-level identifier should carry both UIDs.
            ds = scanner.assoc.last_dataset
            self.assertEqual(str(getattr(ds, "QueryRetrieveLevel", "")), "SERIES")
            self.assertEqual(str(getattr(ds, "SeriesInstanceUID", "")), "1.2.SERIES")

            self.assertIn("Bulk image retrieval", _finding_titles(scanner))

    def test_study_level_when_only_study_uid(self):
        with tempfile.TemporaryDirectory() as tmp:
            scanner = _make_dicom_instance(
                _args(study_uid="1.2.STUDY", series_uid="", output_dir=tmp)
            )
            scanner.logger = Mock()
            scanner.assoc = CGetAssoc(scanner, files=1)

            scanner._cget_retrieve()

            ds = scanner.assoc.last_dataset
            self.assertEqual(str(getattr(ds, "QueryRetrieveLevel", "")), "STUDY")
            self.assertEqual(str(getattr(ds, "StudyInstanceUID", "")), "1.2.STUDY")

    def test_no_uid_fails_before_query(self):
        scanner = _make_dicom_instance(_args(study_uid="", series_uid="", output_dir="/tmp/x"))
        scanner.logger = Mock()
        scanner.assoc = Mock()
        scanner.assoc.is_established = True

        scanner._cget_retrieve()

        scanner.assoc.send_c_get.assert_not_called()
        fail_text = " ".join(str(c.args[0]) for c in scanner.logger.fail.call_args_list if c.args)
        self.assertIn("requires --study-uid or --series-uid", fail_text)

    def test_unexpected_status_warns(self):
        with tempfile.TemporaryDirectory() as tmp:
            scanner = _make_dicom_instance(_args(study_uid="S", series_uid="", output_dir=tmp))
            scanner.logger = Mock()
            # 0xA702 = out of resources -> not in (pending, success) -> warn
            scanner.assoc = CGetAssoc(scanner, files=0, statuses=[0xA702])

            scanner._cget_retrieve()

            warn_text = " ".join(
                str(c.args[0]) for c in scanner.logger.warning.call_args_list if c.args
            )
            self.assertIn("C-GET status", warn_text)

    def test_no_files_no_finding(self):
        with tempfile.TemporaryDirectory() as tmp:
            scanner = _make_dicom_instance(_args(study_uid="S", series_uid="", output_dir=tmp))
            scanner.logger = Mock()
            scanner.assoc = CGetAssoc(scanner, files=0)

            scanner._cget_retrieve()

            self.assertEqual(scanner.results["data"]["cget_results"]["files_retrieved"], 0)
            self.assertNotIn("Bulk image retrieval", _finding_titles(scanner))

    def test_exception_caught(self):
        with tempfile.TemporaryDirectory() as tmp:
            scanner = _make_dicom_instance(_args(study_uid="S", series_uid="", output_dir=tmp))
            scanner.logger = Mock()
            assoc = Mock()
            assoc.is_established = True
            assoc.send_c_get.side_effect = RuntimeError("get failed")
            scanner.assoc = assoc

            scanner._cget_retrieve()

            fail_text = " ".join(
                str(c.args[0]) for c in scanner.logger.fail.call_args_list if c.args
            )
            self.assertIn("C-GET failed", fail_text)

    def test_no_association_fails(self):
        scanner = _make_dicom_instance(_args(study_uid="S", series_uid="", output_dir="/tmp/x"))
        scanner.logger = Mock()
        scanner.assoc = None
        scanner._cget_retrieve()
        fail_text = " ".join(str(c.args[0]) for c in scanner.logger.fail.call_args_list if c.args)
        self.assertIn("No active association", fail_text)


# ===========================================================================
# OperationsMixin._cstore_send
# ===========================================================================
class StoreAssoc:
    def __init__(self, statuses):
        self.is_established = True
        self.statuses = list(statuses)
        self.stored = []

    def send_c_store(self, ds):
        self.stored.append(ds)
        return _status(self.statuses.pop(0))


def _write_dummy_dcm(path: Path):
    """Write a minimal valid DICOM file pynetdicom/pydicom can read back."""
    from pydicom.dataset import FileMetaDataset
    from pydicom.uid import ExplicitVRLittleEndian, generate_uid

    ds = Dataset()
    ds.PatientName = "TEST^EXPORT"
    ds.PatientID = "PT-EXPORT"
    ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.7"  # Secondary Capture
    ds.SOPInstanceUID = generate_uid()
    fm = FileMetaDataset()
    fm.MediaStorageSOPClassUID = ds.SOPClassUID
    fm.MediaStorageSOPInstanceUID = ds.SOPInstanceUID
    fm.TransferSyntaxUID = ExplicitVRLittleEndian
    ds.file_meta = fm
    ds.is_little_endian = True
    ds.is_implicit_VR = False
    ds.save_as(str(path), write_like_original=False)


class TestCStoreSend(unittest.TestCase):
    def test_confirm_gate_blocks_without_confirm(self):
        scanner = _make_dicom_instance(_args(confirm=False, store_file="x.dcm"))
        scanner.logger = Mock()
        scanner.assoc = Mock()
        scanner.assoc.is_established = True

        scanner._cstore_send()

        scanner.assoc.send_c_store.assert_not_called()
        fail_text = " ".join(str(c.args[0]) for c in scanner.logger.fail.call_args_list if c.args)
        self.assertIn("requires --confirm", fail_text)

    def test_upload_success_emits_finding(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "image.dcm"
            _write_dummy_dcm(f)
            scanner = _make_dicom_instance(_args(confirm=True, store_file=str(f), store_dir=None))
            scanner.logger = Mock()
            scanner.assoc = StoreAssoc(statuses=[0x0000])

            scanner._cstore_send()

            res = scanner.results["data"]["cstore_results"]
            self.assertEqual(res["files_uploaded"], 1)
            self.assertEqual(res["files_failed"], 0)
            self.assertEqual(len(scanner.assoc.stored), 1)
            self.assertIn("Unrestricted upload", _finding_titles(scanner))

    def test_directory_glob_and_mixed_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name in ("a.dcm", "b.dcm"):
                _write_dummy_dcm(Path(tmp) / name)
            scanner = _make_dicom_instance(_args(confirm=True, store_file=None, store_dir=tmp))
            scanner.logger = Mock()
            # First accepted (0x0000), second refused (0xA700 out-of-resources)
            scanner.assoc = StoreAssoc(statuses=[0x0000, 0xA700])

            scanner._cstore_send()

            res = scanner.results["data"]["cstore_results"]
            self.assertEqual(res["files_uploaded"], 1)
            self.assertEqual(res["files_failed"], 1)
            warn_text = " ".join(
                str(c.args[0]) for c in scanner.logger.warning.call_args_list if c.args
            )
            self.assertIn("Failed", warn_text)

    def test_no_source_fails(self):
        scanner = _make_dicom_instance(_args(confirm=True, store_file=None, store_dir=None))
        scanner.logger = Mock()
        scanner.assoc = Mock()
        scanner.assoc.is_established = True

        scanner._cstore_send()

        fail_text = " ".join(str(c.args[0]) for c in scanner.logger.fail.call_args_list if c.args)
        self.assertIn("requires --store-file or --store-dir", fail_text)

    def test_empty_directory_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            scanner = _make_dicom_instance(_args(confirm=True, store_file=None, store_dir=tmp))
            scanner.logger = Mock()
            scanner.assoc = Mock()
            scanner.assoc.is_established = True

            scanner._cstore_send()

            fail_text = " ".join(
                str(c.args[0]) for c in scanner.logger.fail.call_args_list if c.args
            )
            self.assertIn("No DICOM files found", fail_text)

    def test_unreadable_file_counts_as_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "corrupt.dcm"
            bad.write_bytes(b"not a dicom file at all")
            scanner = _make_dicom_instance(_args(confirm=True, store_file=str(bad), store_dir=None))
            scanner.logger = Mock()
            scanner.assoc = StoreAssoc(statuses=[0x0000])

            scanner._cstore_send()

            res = scanner.results["data"]["cstore_results"]
            self.assertEqual(res["files_uploaded"], 0)
            self.assertEqual(res["files_failed"], 1)
            # No upload succeeded -> no finding.
            self.assertNotIn("Unrestricted upload", _finding_titles(scanner))

    def test_no_association_fails(self):
        scanner = _make_dicom_instance(_args(confirm=True, store_file="x.dcm"))
        scanner.logger = Mock()
        scanner.assoc = None
        scanner._cstore_send()
        fail_text = " ".join(str(c.args[0]) for c in scanner.logger.fail.call_args_list if c.args)
        self.assertIn("No active association", fail_text)


# ===========================================================================
# OperationsMixin._cmove_request
# ===========================================================================
class MoveAssoc:
    """C-MOVE association. ``script`` is a list of (status_code, kwargs) where
    kwargs set the sub-operation counters on the status object."""

    def __init__(self, script):
        self.is_established = True
        self.script = script
        self.last_dest = None
        self.last_dataset = None

    def send_c_move(self, dataset, dest_aet, model):
        self.last_dest = dest_aet
        self.last_dataset = dataset
        out = []
        for code, counters in self.script:
            s = Mock(spec=["Status"] + list(counters.keys()))
            s.Status = code
            for k, v in counters.items():
                setattr(s, k, v)
            out.append((s, None))
        return iter(out)


class TestCMoveRequest(unittest.TestCase):
    def test_confirm_gate(self):
        scanner = _make_dicom_instance(_args(confirm=False, dest_aet="REMOTE", study_uid="S"))
        scanner.logger = Mock()
        scanner.assoc = Mock()
        scanner.assoc.is_established = True

        scanner._cmove_request()

        scanner.assoc.send_c_move.assert_not_called()
        fail_text = " ".join(str(c.args[0]) for c in scanner.logger.fail.call_args_list if c.args)
        self.assertIn("requires --confirm", fail_text)

    def test_missing_dest_aet_fails(self):
        scanner = _make_dicom_instance(
            _args(confirm=True, dest_aet="", study_uid="S", series_uid="")
        )
        scanner.logger = Mock()
        scanner.assoc = Mock()
        scanner.assoc.is_established = True

        scanner._cmove_request()

        scanner.assoc.send_c_move.assert_not_called()
        fail_text = " ".join(str(c.args[0]) for c in scanner.logger.fail.call_args_list if c.args)
        self.assertIn("requires --dest-aet", fail_text)

    def test_missing_uid_fails(self):
        scanner = _make_dicom_instance(
            _args(confirm=True, dest_aet="REMOTE", study_uid="", series_uid="")
        )
        scanner.logger = Mock()
        scanner.assoc = Mock()
        scanner.assoc.is_established = True

        scanner._cmove_request()

        scanner.assoc.send_c_move.assert_not_called()
        fail_text = " ".join(str(c.args[0]) for c in scanner.logger.fail.call_args_list if c.args)
        self.assertIn("requires --study-uid or --series-uid", fail_text)

    def test_successful_transfer_counts_and_finding(self):
        scanner = _make_dicom_instance(
            _args(confirm=True, dest_aet="REMOTE_PACS", study_uid="1.2.S", series_uid="")
        )
        scanner.logger = Mock()
        # Pending with running counters, then terminal success.
        scanner.assoc = MoveAssoc(
            [
                (0xFF00, {"NumberOfCompletedSuboperations": 2, "NumberOfFailedSuboperations": 0}),
                (0x0000, {"NumberOfCompletedSuboperations": 3, "NumberOfFailedSuboperations": 0}),
            ]
        )

        scanner._cmove_request()

        res = scanner.results["data"]["cmove_results"]
        self.assertEqual(res["completed"], 3)
        self.assertEqual(res["dest_aet"], "REMOTE_PACS")
        self.assertEqual(scanner.assoc.last_dest, "REMOTE_PACS")
        # STUDY-level identifier
        self.assertEqual(
            str(getattr(scanner.assoc.last_dataset, "QueryRetrieveLevel", "")), "STUDY"
        )

        success_text = " ".join(
            str(c.args[0]) for c in scanner.logger.success.call_args_list if c.args
        )
        self.assertIn("C-MOVE completed", success_text)
        self.assertIn("Open transfer", _finding_titles(scanner))

    def test_warning_status_branch(self):
        scanner = _make_dicom_instance(
            _args(confirm=True, dest_aet="R", study_uid="", series_uid="1.2.SE")
        )
        scanner.logger = Mock()
        scanner.assoc = MoveAssoc(
            [
                (
                    0xB000,
                    {
                        "NumberOfCompletedSuboperations": 1,
                        "NumberOfFailedSuboperations": 0,
                        "NumberOfWarningSuboperations": 2,
                    },
                )
            ]
        )

        scanner._cmove_request()

        warn_text = " ".join(
            str(c.args[0]) for c in scanner.logger.warning.call_args_list if c.args
        )
        self.assertIn("completed with warnings", warn_text)
        # SERIES-level identifier (series_uid given, no study_uid).
        self.assertEqual(
            str(getattr(scanner.assoc.last_dataset, "QueryRetrieveLevel", "")), "SERIES"
        )

    def test_failure_status_branch_no_finding(self):
        scanner = _make_dicom_instance(
            _args(confirm=True, dest_aet="R", study_uid="S", series_uid="")
        )
        scanner.logger = Mock()
        # Refused: unable to process, 0 completed.
        scanner.assoc = MoveAssoc(
            [(0xA801, {"NumberOfCompletedSuboperations": 0, "NumberOfFailedSuboperations": 1})]
        )

        scanner._cmove_request()

        self.assertEqual(scanner.results["data"]["cmove_results"]["completed"], 0)
        fail_text = " ".join(str(c.args[0]) for c in scanner.logger.fail.call_args_list if c.args)
        self.assertIn("C-MOVE failed: status", fail_text)
        self.assertNotIn("Open transfer", _finding_titles(scanner))

    def test_exception_caught(self):
        scanner = _make_dicom_instance(
            _args(confirm=True, dest_aet="R", study_uid="S", series_uid="")
        )
        scanner.logger = Mock()
        assoc = Mock()
        assoc.is_established = True
        assoc.send_c_move.side_effect = RuntimeError("move aborted")
        scanner.assoc = assoc

        scanner._cmove_request()

        fail_text = " ".join(str(c.args[0]) for c in scanner.logger.fail.call_args_list if c.args)
        self.assertIn("C-MOVE failed", fail_text)

    def test_no_association_fails(self):
        scanner = _make_dicom_instance(_args(confirm=True, dest_aet="R", study_uid="S"))
        scanner.logger = Mock()
        scanner.assoc = None
        scanner._cmove_request()
        fail_text = " ".join(str(c.args[0]) for c in scanner.logger.fail.call_args_list if c.args)
        self.assertIn("No active association", fail_text)


# ===========================================================================
# EnumerationMixin._aet_brute_force
# ===========================================================================
class BruteAE:
    """Fake pynetdicom AE. ``verdicts`` maps the *calling* AE title -> outcome:
    "ok" (established + echo 0x0000), "echo_fail" (established, echo non-zero),
    "reject" (not established), or "raise" (associate raises)."""

    instances = []

    def __init__(self, verdicts):
        self.verdicts = verdicts
        BruteAE.reset()

    @classmethod
    def reset(cls):
        cls.instances = []

    def __call__(self, ae_title="OIDA"):
        inst = _BruteAEInstance(ae_title, self.verdicts)
        BruteAE.instances.append(inst)
        return inst


class _BruteAEInstance:
    def __init__(self, ae_title, verdicts):
        self.ae_title = ae_title
        self.verdicts = verdicts
        self.network_timeout = None
        self.acse_timeout = None
        self.connection_timeout = None
        self._contexts = []

    def add_requested_context(self, ctx):
        self._contexts.append(ctx)

    def associate(self, ip, port, ae_title="ANY", tls_args=None):
        verdict = self.verdicts.get(self.ae_title, "reject")
        if verdict == "raise":
            raise RuntimeError("connection refused")
        assoc = Mock()
        if verdict in ("ok", "echo_fail"):
            assoc.is_established = True
            assoc.send_c_echo.return_value = _status(0x0000 if verdict == "ok" else 0xA700)
        else:
            assoc.is_established = False
        assoc.release.return_value = None
        return assoc


class TestAETBruteForce(unittest.TestCase):
    def test_confirm_gate_blocks(self):
        scanner = _make_dicom_instance(_args(confirm=False, aet_brute=True, common_ae=True))
        scanner.logger = Mock()
        scanner._aet_brute_force()
        self.assertNotIn("aet_brute", scanner.results["data"])
        fail_text = " ".join(str(c.args[0]) for c in scanner.logger.fail.call_args_list if c.args)
        self.assertIn("requires --confirm", fail_text)

    def test_common_ae_classifies_valid_and_rejected(self):
        import oida.protocols.dicom as pkg

        # Mix of outcomes across the common vendor list.
        verdicts = {"ANY": "ok", "*": "echo_fail", "PACS": "reject", "STORESCU": "raise"}
        fake_ae = BruteAE(verdicts)
        scanner = _make_dicom_instance(
            _args(confirm=True, aet_brute=True, ae_wordlist=None, common_ae=True)
        )
        scanner.logger = Mock()
        scanner.called_aet = "ANY"

        orig = pkg.AE
        pkg.AE = fake_ae
        try:
            scanner._aet_brute_force()
        finally:
            pkg.AE = orig

        res = scanner.results["data"]["aet_brute"]
        # "ANY" (echo ok) and "*" (echo fail but associated) are both valid.
        self.assertIn("ANY", res["valid"])
        self.assertIn("*", res["valid"])
        self.assertEqual(
            res["tested_count"],
            len(
                __import__(
                    "oida.protocols.dicom.cli_runner", fromlist=["DEFAULT_AET_WORDLIST"]
                ).DEFAULT_AET_WORDLIST
            ),
        )
        self.assertGreater(res["rejected_count"], 0)

    def test_many_valid_triggers_weak_whitelist_finding(self):
        import oida.protocols.dicom as pkg
        from oida.protocols.dicom.cli_runner import DEFAULT_AET_WORDLIST

        # Accept every AE title -> > 5 valid -> weak AET whitelist finding.
        verdicts = {a: "ok" for a in DEFAULT_AET_WORDLIST}
        fake_ae = BruteAE(verdicts)
        scanner = _make_dicom_instance(
            _args(confirm=True, aet_brute=True, ae_wordlist=None, common_ae=True)
        )
        scanner.logger = Mock()
        scanner.called_aet = "ANY"

        orig = pkg.AE
        pkg.AE = fake_ae
        try:
            scanner._aet_brute_force()
        finally:
            pkg.AE = orig

        self.assertGreater(len(scanner.results["data"]["aet_brute"]["valid"]), 5)
        self.assertIn("No authentication", _finding_titles(scanner))

    def test_custom_wordlist_file_loaded(self):
        import oida.protocols.dicom as pkg

        with tempfile.TemporaryDirectory() as tmp:
            wl = Path(tmp) / "aets.txt"
            wl.write_text("# comment line\nCUSTOM1\nCUSTOM2\n\n")
            verdicts = {"CUSTOM1": "ok", "CUSTOM2": "reject"}
            fake_ae = BruteAE(verdicts)
            scanner = _make_dicom_instance(
                _args(confirm=True, aet_brute=str(wl), ae_wordlist=str(wl), common_ae=False)
            )
            scanner.logger = Mock()
            scanner.called_aet = "ANY"

            orig = pkg.AE
            pkg.AE = fake_ae
            try:
                scanner._aet_brute_force()
            finally:
                pkg.AE = orig

            res = scanner.results["data"]["aet_brute"]
            self.assertEqual(res["tested_count"], 2)  # comment + blank stripped
            self.assertEqual(res["valid"], ["CUSTOM1"])
            self.assertEqual(res["rejected_count"], 1)


if __name__ == "__main__":
    unittest.main()
