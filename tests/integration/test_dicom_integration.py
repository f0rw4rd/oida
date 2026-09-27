"""
DICOM Protocol Integration Tests

Tests oida dicom scanner against Docker mock service.
Uses structured JSON log assertions for precise validation.

Mock Server Data (from docker/mocks/services/dicom_server.py):
  Server AET:     "MOCK_PACS"
  Port:           11112 (open, accepts all AETs)
  Strict Port:    11113 (AET whitelist)

  Patients (5):
    PT001 DOE^JOHN        3 studies   (CT, MR, CT)
    PT002 SMITH^JANE      5 studies   (US, MG, CT, MG, PT)
    PT003 JOHNSON^ROBERT  2 studies   (XA, CT)
    PT004 WILLIAMS^MARY   1 study     (CR)
    PT005 BROWN^DAVID     8 studies   (CT, US, NM, MR, CT, DR, RF, CT)

  Total Studies: 19 (spanning 2015-2024 for --time-analysis)
  Total Series:  13 (with device/personnel metadata)
  Modalities:    CT, MR, US, MG, XA, NM, CR, DR, RF, PT

  Personnel (for --enum-operators):
    TECH^SARAH^M, TECH^ROBERT^J, TECH^EMILY^K, SONOGRAPHER^MARY^A,
    MAMMO^TECH^SUE, MAMMO^TECH^RITA, NUCLEAR^TECH^JIM, CATH^TECH^BOB,
    XRAY^TECH^DAN, TECH^OLD^TOM, FLUORO^TECH^ANN

  Stations/Devices (for --enum-devices):
    CT_SCANNER_01, CT_SCANNER_03, CT_SCANNER_OLD, CT_CARDIAC_01,
    MRI_SCANNER_02, US_BREAST_01, US_GENERAL_01, MAMMO_01, MAMMO_02,
    PET_CT_01, CATH_LAB_01, CR_ER_01, DR_ORTHO_01, GAMMA_CAM_01, FLUORO_01

  Manufacturers:
    GE Healthcare, Siemens Healthineers, Philips, Canon Medical,
    Hologic, Carestream, Fujifilm, Shimadzu, Toshiba

  Institutions:
    GENERAL HOSPITAL, WOMENS HEALTH CENTER, CARDIAC CENTER,
    CANCER CENTER, ORTHOPEDIC CLINIC

  UPS/Worklist (5 items):
    CT Chest Contrast (SCHEDULED), MR Brain Gadolinium (IN PROGRESS),
    US Abdomen Complete (COMPLETED), XA Cardiac Cath (SCHEDULED),
    CT Abdomen Pelvis (CANCELED)

  Accession Numbers: ACC001-ACC019

  NOTE: Mock supports UPS Query (UnifiedProcedureStepQuery) but does NOT
  support ModalityWorklistInformationFind. The scanner's --worklist flag
  uses MWL, so worklist tests are Category C (expect graceful failure).

Test Classification Summary
---------------------------------------------------------------------------
Category A (strict -- mock supports, assert success + validate data):  37 tests
Category B (conditional -- mock may not support, accept 0 or 1):       18 tests
Category C (error handling -- assert failure / doesn't crash):         10 tests
Skipped (dead flag -- defined in proto_args but not consumed):          2 tests
Total defined in file:                                                 67 tests
Inherited from base (already have return code assertions):              4 tests
Grand total (collected by pytest):                                     71 tests
---------------------------------------------------------------------------
NOTE: 6 tests override base class methods to add return code assertions.
      Base class tests test_service_is_available, test_help_command,
      test_basic_discovery, and test_invalid_target already have adequate
      assertions and are inherited unchanged.

Security Finding Coverage (16 tests):
  "No encryption"                 test_finding_no_encryption [A]
  "No encryption" absent w/ TLS   test_finding_no_encryption_absent_with_tls [B]
  "Weak AET whitelist"            test_finding_weak_aet_whitelist [A]
  "Weak AET whitelist" absent     test_finding_weak_aet_whitelist_absent_with_custom_aet [A]
  "No authentication"             test_finding_no_authentication_aet_brute [A]
  "Permissive AET policy"         test_finding_permissive_aet_policy [B]
  "Unrestricted query access"     test_finding_unrestricted_query_access [A]
  "Unrestricted query" absent     test_finding_unrestricted_query_absent_with_specific_filter [A]
  "Bulk image retrieval"          test_finding_bulk_image_retrieval_cget [B]
  "Open transfer"                 test_finding_open_transfer_cmove [B]
  "Mass data exfiltration"        test_finding_mass_data_exfiltration_dump_all [B]
  "Unrestricted worklist access"  test_finding_unrestricted_worklist_access [C]
  Multiple findings combo         test_finding_multiple_findings_on_basic_scan [A]
  Dual query findings             test_finding_cfind_wildcard_produces_dual_findings [A]
  All brute findings              test_finding_aet_brute_all_findings [A]
  Event structure                 test_finding_event_structure_has_required_fields [A]

Flag Coverage Matrix (proto_args.py):
  --port                    [A] test_basic_discovery (inherited)
  --timeout                 [A] test_basic_discovery (inherited)
  --aet                     [A] test_custom_ae_titles
  --called-aet              [A] test_custom_ae_titles
  --max-pdu                 [A] test_max_pdu_size
  --find                    [A] test_c_find_patient_level, test_c_find_study_level
  --get                     [B] test_c_get_retrieve
  --store                   [B] test_c_store_missing_file
  --move                    [B] test_c_move_transfer
  --probe-ops               [A] test_probe_ops
  --dump-all                [B] test_dump_all_bulk_export
  --query-level PATIENT     [A] test_c_find_patient_level
  --query-level STUDY       [A] test_c_find_study_level
  --query-level SERIES      [A] test_c_find_series_level
  --query-level IMAGE       [C] test_c_find_image_level
  --patient-id              [A] test_c_find_patient_id_filter
  --patient-name            [A] test_c_find_patient_name_filter
  --study-date              [A] test_c_find_study_date_filter
  --modality                [A] test_c_find_modality_filter
  --accession-number        [A] test_c_find_accession_number_filter
  --study-uid               [A] test_c_find_study_uid_filter
  --series-uid              [A] test_c_find_series_uid_filter
  --max-results             [A] test_c_find_max_results
  --dump-tags               [A] test_c_find_dump_tags
  --dump-tags --phi-only    [A] test_c_find_dump_tags_phi_only
  --metadata                [A] test_c_find_metadata
  --extract-fields          [A] test_c_find_extract_fields
  --enum-operators          [A] test_enum_operators
  --enum-devices            [A] test_enum_devices
  --time-analysis           [A] test_time_analysis
  --worklist                [C] test_worklist_query (mock lacks MWL)
  --worklist-modality       [C] test_worklist_modality_filter (mock lacks MWL)
  --worklist-date           [C] test_worklist_date_filter (mock lacks MWL)
  --worklist-station        [C] test_worklist_station_filter (mock lacks MWL)
  --output-dir              [B] test_dump_all_bulk_export
  --dest-aet                [B] test_c_move_transfer
  --store-file              [B] test_c_store_missing_file
  --store-dir               [A] test_c_store_dir_uploads_files
  --max-patients            [B] test_dump_all_bulk_export
  --max-studies             [B] test_dump_all_bulk_export
  --aet-brute               [A] test_brute_ae_open_server, [B] test_brute_ae_strict_server
  --common-ae               [A] test_common_ae_titles
  --ae-wordlist             [A] test_ae_wordlist_custom_file
  --tls                     [B] test_tls_connection
  --discover/--quick/--full [B] test_discover_mode, test_quick_mode, test_full_mode
  --deep-scan               [B] test_deep_scan_mode
  --fuzz (no --confirm)     [C] test_fuzz_requires_confirm
  --fuzz --confirm          [C] test_fuzz_with_confirm
  invalid host              [C] test_invalid_target (inherited)
  wrong port                [C] test_connection_refused (inherited)
"""

import contextlib
import json
import socket
import threading
import time

import pytest
from typing import Optional

from tests.integration.base_protocol_test import BaseProtocolIntegrationTest
from tests.integration.conftest import MOCK_HOST
from tests.service_gate import require_port


# DICOM SCP mocks use pynetdicom's default maximum_associations (~10); under
# -n auto the scanner's own multi-association brute-force plus parallel workers
# exceed that cap and tests flake en masse. Pin the module to one xdist worker.
# Honored only under `--dist loadgroup`. Mirrors test_iec104_integration.py.
pytestmark = pytest.mark.xdist_group("dicom_service")


# ---------------------------------------------------------------------------
# Known Mock Data Constants (extracted from dicom_server.py)
# ---------------------------------------------------------------------------
MOCK_SERVER_AET = "MOCK_PACS"
MOCK_SERVER_PORT = 11112
MOCK_PATIENT_NAMES = ["DOE^JOHN", "SMITH^JANE", "JOHNSON^ROBERT", "WILLIAMS^MARY", "BROWN^DAVID"]
MOCK_PATIENT_IDS = ["PT001", "PT002", "PT003", "PT004", "PT005"]
MOCK_MODALITIES = ["CT", "MR", "US", "MG", "XA", "NM", "CR", "DR", "RF", "PT"]
MOCK_INSTITUTIONS = [
    "GENERAL HOSPITAL",
    "WOMENS HEALTH CENTER",
    "CARDIAC CENTER",
    "CANCER CENTER",
    "ORTHOPEDIC CLINIC",
]
MOCK_MANUFACTURERS = [
    "GE Healthcare",
    "Siemens Healthineers",
    "Philips",
    "Canon Medical",
    "Hologic",
    "Carestream",
    "Fujifilm",
    "Shimadzu",
    "Toshiba",
]
# Known study descriptions for content validation (avoid matching "ct" in "connected")
MOCK_STUDY_DESCRIPTIONS = [
    "CT CHEST WITH CONTRAST",
    "MR BRAIN WITH GADOLINIUM",
    "CT ABDOMEN PELVIS",
    "US BREAST BILATERAL",
    "MG SCREENING BILATERAL",
    "XA CARDIAC CATH",
    "CT CORONARY ANGIO",
    "CR CHEST PA LAT",
    "CT HEAD WITHOUT CONTRAST",
    "NM BONE SCAN WHOLE BODY",
    "MR LUMBAR SPINE",
    "DR KNEE LEFT 3 VIEWS",
    "RF UPPER GI SERIES",
    "CT CHEST ABDOMEN PELVIS",
    "PET CT ONCOLOGY",
    "CT CHEST LOW DOSE SCREENING",
    "US ABDOMEN COMPLETE",
    "MG DIAGNOSTIC LEFT",
    "CT SPINE CERVICAL",
]
MOCK_STUDY_COUNT = 19
MOCK_PATIENT_COUNT = 5

# Known study UIDs for C-GET/C-MOVE/C-FIND filter tests
MOCK_STUDY_UID = "1.2.840.10008.5.1.4.1.1.1.1"  # DOE^JOHN CT CHEST
MOCK_SERIES_UID = "1.2.840.10008.5.1.4.1.1.1.1.1"  # SCOUT series in above study

# Known accession numbers
MOCK_ACCESSION_FIRST = "ACC001"  # DOE^JOHN CT CHEST study

# Known operator/station names for enumeration validation
MOCK_OPERATORS = ["TECH^SARAH^M", "TECH^ROBERT^J", "TECH^EMILY^K"]
MOCK_STATIONS = ["CT_SCANNER_01", "MRI_SCANNER_02", "CATH_LAB_01"]
# Known series descriptions
MOCK_SERIES_DESCRIPTIONS = [
    "SCOUT",
    "AXIAL IMAGES 5MM",
    "AXIAL IMAGES 1.25MM",
    "CORONAL REFORMATS",
    "3-PLANE LOCALIZER",
    "AX T1 MPRAGE",
    "AX T2 FLAIR",
    "AX DWI",
    "LEFT CORONARY ARTERY",
    "RIGHT CORONARY ARTERY",
    "LEFT VENTRICULOGRAM",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _all_messages(log) -> str:
    """Concatenate all log messages into a single lowercase string for searching."""
    return " ".join(e.get("message", "") for e in log.events).lower()


def _assert_log_has_events(result, min_count=1):
    """Assert that the scan_log exists and has at least min_count events."""
    assert result.scan_log is not None, "scan_log should be populated when json_log=True"
    result.scan_log.assert_has_events(min_count=min_count)


def _assert_log_event_structure(log):
    """Validate that every event in the log has the required fields."""
    required = {"timestamp", "level", "event_type", "module", "message"}
    for i, event in enumerate(log.events):
        missing = required - set(event.keys())
        assert not missing, f"Event {i} missing fields: {missing}"


def _combined_text(result, log=None) -> str:
    """Return lowercase combined output + log messages for broad searches."""
    parts = [result.combined_output.lower()]
    if log is not None:
        parts.append(_all_messages(log))
    return " ".join(parts)


@pytest.mark.dicom
class TestDicomIntegration(BaseProtocolIntegrationTest):
    """Integration tests for DICOM protocol scanner"""

    @property
    def protocol_name(self) -> str:
        return "dicom"

    @property
    def default_port(self) -> int:
        return 11112

    def get_target(self, host: str = MOCK_HOST, port: Optional[int] = None) -> str:
        return host

    # ========================================================================
    # Category A: Strict tests (mock supports, assert success + validate data)
    # ========================================================================

    def test_c_echo_discovery(self, cli_runner, target, port):
        """Test basic discovery triggers C-ECHO and association [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"Basic discovery failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log
        _assert_log_event_structure(log)

        text = _combined_text(result, log)
        # Check for DICOM-specific indicators, not generic words
        assert any(x in text for x in ["echo", "association", "mock_pacs", "dicom", "c-echo"]), (
            f"Expected DICOM-specific response indicators in output: {text[:500]}"
        )

    def test_c_echo_security_findings(self, cli_runner, target, port):
        """Test basic discovery generates security findings [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"Discovery failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        security = log.get_security_findings()
        assert len(security) >= 1, (
            "Scanner must produce at least 'No encryption' finding when --tls not used"
        )
        finding_texts = " ".join(
            f.get("data", {}).get("finding", "") + " " + f.get("message", "") for f in security
        ).lower()
        assert any(x in finding_texts for x in ["encrypt", "plaintext", "no encryption"]), (
            f"Expected 'No encryption' security finding. Got: {finding_texts}"
        )

    def test_c_find_patient_level(self, cli_runner, target, port):
        """Test C-FIND at PATIENT level returns known patients [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--find",
            "--query-level",
            "PATIENT",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"C-FIND PATIENT failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log
        _assert_log_event_structure(log)

        text = _combined_text(result, log)
        assert any(name.lower() in text for name in MOCK_PATIENT_NAMES), (
            f"Expected at least one patient name in output. "
            f"Known patients: {MOCK_PATIENT_NAMES}. Got: {text[:500]}"
        )

    def test_c_find_study_level(self, cli_runner, target, port):
        """Test C-FIND at STUDY level returns study descriptions [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--find",
            "--query-level",
            "STUDY",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"C-FIND STUDY failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log
        _assert_log_event_structure(log)

        text = _combined_text(result, log)
        # Check for actual study descriptions from mock, NOT "ct" which matches "connected"
        assert any(desc.lower() in text for desc in MOCK_STUDY_DESCRIPTIONS), (
            f"Expected at least one study description in output. "
            f"Known descriptions: {MOCK_STUDY_DESCRIPTIONS[:5]}. Got: {text[:500]}"
        )

    def test_c_find_series_level(self, cli_runner, target, port):
        """Test C-FIND at SERIES level returns series data [Category A]

        NOTE: Scanner requires --study-uid for SERIES level.
        We pass the known study UID for DOE^JOHN CT CHEST.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--find",
            "--query-level",
            "SERIES",
            "--study-uid",
            MOCK_STUDY_UID,
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"C-FIND SERIES failed: {result.stderr}"
        _assert_log_has_events(result)
        text = _combined_text(result, result.scan_log)
        # Check for actual series descriptions from mock
        assert any(desc.lower() in text for desc in MOCK_SERIES_DESCRIPTIONS), (
            f"Expected series descriptions like SCOUT, AXIAL in output: {text[:500]}"
        )

    def test_c_find_patient_id_filter(self, cli_runner, target, port):
        """Test C-FIND filtered by patient ID returns correct patient [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--find",
            "--patient-id",
            "PT001",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"C-FIND patient-id filter failed: {result.stderr}"
        _assert_log_has_events(result)
        text = _combined_text(result, result.scan_log)
        assert "doe" in text or "john" in text or "pt001" in text, (
            f"Expected DOE^JOHN or PT001 in output for patient-id PT001: {text[:500]}"
        )

    def test_c_find_patient_name_filter(self, cli_runner, target, port):
        """Test C-FIND filtered by patient name wildcard [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--find",
            "--patient-name",
            "DOE*",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"C-FIND patient-name filter failed: {result.stderr}"
        _assert_log_has_events(result)
        text = _combined_text(result, result.scan_log)
        assert "doe" in text, f"Expected DOE in output for patient-name DOE*: {text[:500]}"

    def test_c_find_modality_filter(self, cli_runner, target, port):
        """Test C-FIND filtered by modality CT [Category A]

        Uses --query-level STUDY to get study descriptions containing CT studies.
        Avoids matching "ct" inside words like "connected" or "context".
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--find",
            "--modality",
            "CT",
            "--query-level",
            "STUDY",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"C-FIND modality filter failed: {result.stderr}"
        _assert_log_has_events(result)
        text = _combined_text(result, result.scan_log)
        # Check for CT study descriptions from mock, not just "ct"
        ct_descriptions = [d for d in MOCK_STUDY_DESCRIPTIONS if d.startswith("CT ")]
        assert any(desc.lower() in text for desc in ct_descriptions), (
            f"Expected CT study descriptions like 'ct chest' or 'ct abdomen' in output. "
            f"Got: {text[:500]}"
        )

    def test_c_find_study_date_filter(self, cli_runner, target, port):
        """Test C-FIND filtered by study date range [Category A]

        Mock has 4 studies in 2024: CT ABDOMEN PELVIS, PET CT ONCOLOGY,
        CR CHEST PA LAT, CT CHEST ABDOMEN PELVIS.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--find",
            "--study-date",
            "20240101-20241231",
            "--query-level",
            "STUDY",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"C-FIND study-date filter failed: {result.stderr}"
        _assert_log_has_events(result)
        text = _combined_text(result, result.scan_log)
        # Check for specific 2024 study descriptions
        studies_2024 = [
            "ct abdomen pelvis",
            "pet ct oncology",
            "cr chest pa lat",
            "ct chest abdomen pelvis",
        ]
        assert any(desc in text for desc in studies_2024), (
            f"Expected 2024 study descriptions in output. "
            f"Known 2024 studies: {studies_2024}. Got: {text[:500]}"
        )

    def test_c_find_accession_number_filter(self, cli_runner, target, port):
        """Test C-FIND filtered by accession number [Category A]

        ACC001 is DOE^JOHN's CT CHEST WITH CONTRAST study.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--find",
            "--query-level",
            "STUDY",
            "--accession-number",
            MOCK_ACCESSION_FIRST,
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"C-FIND accession-number filter failed: {result.stderr}"
        _assert_log_has_events(result)
        text = _combined_text(result, result.scan_log)
        # ACC001 is DOE^JOHN CT CHEST WITH CONTRAST -- assert specific content
        assert "doe" in text or "chest" in text, (
            f"Expected DOE or CHEST for accession ACC001 (CT CHEST WITH CONTRAST): {text[:500]}"
        )

    def test_probe_ops(self, cli_runner, target, port):
        """Test --probe-ops enumerates SOP classes [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--probe-ops",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"--probe-ops failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log
        _assert_log_event_structure(log)

        text = _combined_text(result, log)
        # probe-ops displays SOP class information -- check for DICOM-specific terms
        assert any(
            x in text
            for x in [
                "verification",
                "sop",
                "transfer syntax",
                "c-find",
                "c-get",
                "c-move",
                "c-store",
            ]
        ), f"Expected SOP class/transfer syntax info in output: {text[:500]}"

    def test_custom_ae_titles(self, cli_runner, target, port):
        """Test --aet and --called-aet association succeeds [Category A]

        Verify both custom AE titles appear in output.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--aet",
            "SCANNER",
            "--called-aet",
            "MOCK_PACS",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"Custom AE title association failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log
        _assert_log_event_structure(log)

        text = _combined_text(result, log)
        # Verify both AE titles are reflected in scanner output
        assert "scanner" in text or "mock_pacs" in text, (
            f"Expected custom AET names 'SCANNER' or 'MOCK_PACS' in output: {text[:500]}"
        )

    def test_enum_operators(self, cli_runner, target, port):
        """Test --enum-operators enumerates personnel from study metadata [Category A]

        Mock has 11 unique operators. Scanner displays them under
        "Operators/Technologists", "Performing Physicians", etc.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--enum-operators",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"--enum-operators failed: {result.stderr}"
        _assert_log_has_events(result)
        text = _combined_text(result, result.scan_log)
        # Check for actual mock operator names, not generic words
        assert any(op.lower() in text for op in MOCK_OPERATORS), (
            f"Expected at least one known operator name in output. "
            f"Known operators: {MOCK_OPERATORS}. Got: {text[:500]}"
        )

    def test_enum_devices(self, cli_runner, target, port):
        """Test --enum-devices enumerates stations and equipment [Category A]

        Mock has 15 unique stations and 9 manufacturers.
        Scanner outputs "Station Names/Hostnames" and "Manufacturers" sections.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--enum-devices",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"--enum-devices failed: {result.stderr}"
        _assert_log_has_events(result)
        text = _combined_text(result, result.scan_log)
        # Check for actual mock station names and manufacturers
        assert any(sta.lower() in text for sta in MOCK_STATIONS), (
            f"Expected at least one known station name in output. "
            f"Known stations: {MOCK_STATIONS}. Got: {text[:500]}"
        )
        # Also verify at least one manufacturer appears
        assert any(mfr.lower() in text for mfr in MOCK_MANUFACTURERS), (
            f"Expected at least one manufacturer in output. "
            f"Known manufacturers: {MOCK_MANUFACTURERS[:5]}. Got: {text[:500]}"
        )

    def test_time_analysis(self, cli_runner, target, port):
        """Test --time-analysis shows date distribution spanning 2015-2024 [Category A]

        Scanner outputs "Oldest study: 2015-01-05" and "Newest study: 2024-12-18"
        with year distribution and retention window.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--time-analysis",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"--time-analysis failed: {result.stderr}"
        _assert_log_has_events(result)
        text = _combined_text(result, result.scan_log)
        # Studies span 2015-2024 -- both endpoints must appear
        assert "2015" in text, f"Expected oldest year 2015 in time analysis output: {text[:500]}"
        assert "2024" in text, f"Expected newest year 2024 in time analysis output: {text[:500]}"
        assert "retention" in text or "oldest" in text, (
            f"Expected 'retention' or 'oldest' in time analysis output: {text[:500]}"
        )

    def test_brute_ae_open_server(self, cli_runner, target, port):
        """Test --aet-brute against open server (accepts all AETs) [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--aet-brute",
            "--confirm",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"AET brute force failed on open server: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        text = _combined_text(result, log)
        assert "brute force" in text or "valid ae" in text or "valid:" in text, (
            f"Expected AET brute force results summary: {text[:500]}"
        )
        # Open mock (MOCK_PACS) accepts any AET. The brute-force tests >5 AE
        # Titles and accepts all of them, so the weak-whitelist finding must
        # fire (only emitted when len(valid_aets) > 5).
        log.assert_security_finding("No authentication")
        assert "valid:" in text, (
            f"Open PACS brute-force should report valid AE Titles: {text[:500]}"
        )

    def test_c_find_max_results(self, cli_runner, target, port):
        """Test C-FIND with --max-results limit [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--find",
            "--max-results",
            "3",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"max-results query failed: {result.stderr}"
        _assert_log_has_events(result)
        text = _combined_text(result, result.scan_log)
        assert any(name.lower() in text for name in MOCK_PATIENT_NAMES), (
            f"Expected patient names in max-results output: {text[:500]}"
        )
        assert "c-find results" in text or "found" in text, (
            f"Expected result count summary in output: {text[:500]}"
        )

    def test_c_find_metadata(self, cli_runner, target, port):
        """Test C-FIND with --metadata extraction [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--find",
            "--metadata",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"metadata query failed: {result.stderr}"
        _assert_log_has_events(result)
        text = _combined_text(result, result.scan_log)
        # --metadata with default PATIENT level should return patient names
        assert any(name.lower() in text for name in MOCK_PATIENT_NAMES), (
            f"Expected patient names with --metadata: {text[:500]}"
        )

    def test_c_find_dump_tags(self, cli_runner, target, port):
        """Test C-FIND with --dump-tags [Category A]

        --dump-tags activates _extract_all_tags which dumps all DICOM tags.
        Scanner outputs "PHI: PatientName: ..." for PHI tags.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--find",
            "--dump-tags",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"dump-tags failed: {result.stderr}"
        _assert_log_has_events(result)
        text = _combined_text(result, result.scan_log)
        # dump-tags outputs "PHI: PatientName: DOE^JOHN" and similar tags
        assert "patientname" in text or "patientid" in text or "phi:" in text, (
            f"Expected DICOM tag names (PatientName, PatientID) in dump-tags output: {text[:500]}"
        )

    def test_c_find_dump_tags_phi_only(self, cli_runner, target, port):
        """Test C-FIND with --dump-tags --phi-only [Category A]

        --phi-only filters to only PHI-containing tags.
        Scanner outputs "PHI: ..." lines and "N PHI tags found".
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--find",
            "--dump-tags",
            "--phi-only",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"phi-only tag dump failed: {result.stderr}"
        _assert_log_has_events(result)
        text = _combined_text(result, result.scan_log)
        assert any(x in text for x in ["patientname", "patientid", "doe^john", "phi tags found"]), (
            f"Expected PHI tag names or patient data in phi-only output: {text[:500]}"
        )

    def test_c_find_extract_fields(self, cli_runner, target, port):
        """Test C-FIND with --extract-fields [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--find",
            "--metadata",
            "--extract-fields",
            "PatientName,StudyDate",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"extract-fields failed: {result.stderr}"
        _assert_log_has_events(result)
        text = _combined_text(result, result.scan_log)
        assert any(name.lower() in text for name in MOCK_PATIENT_NAMES), (
            f"Expected patient names with --extract-fields --metadata: {text[:500]}"
        )

    def test_c_find_study_uid_filter(self, cli_runner, target, port):
        """Test C-FIND filtered by --study-uid [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--find",
            "--query-level",
            "STUDY",
            "--study-uid",
            MOCK_STUDY_UID,
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"study-uid filter failed: {result.stderr}"
        _assert_log_has_events(result)
        text = _combined_text(result, result.scan_log)
        # This study is DOE^JOHN's CT CHEST WITH CONTRAST
        assert "doe" in text or "chest" in text, (
            f"Expected DOE or CHEST for study UID filter (CT CHEST): {text[:500]}"
        )

    def test_c_find_series_uid_filter(self, cli_runner, target, port):
        """Test C-FIND at SERIES level with --series-uid filter [Category A]

        Filters to SCOUT series in DOE^JOHN's CT CHEST study.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--find",
            "--query-level",
            "SERIES",
            "--study-uid",
            MOCK_STUDY_UID,
            "--series-uid",
            MOCK_SERIES_UID,
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"series-uid filter failed: {result.stderr}"
        _assert_log_has_events(result)
        text = _combined_text(result, result.scan_log)
        # MOCK_SERIES_UID is the SCOUT series -- assert specific description
        assert "scout" in text or "c-find results" in text, (
            f"Expected SCOUT series description in output: {text[:500]}"
        )

    def test_max_pdu_size(self, cli_runner, target, port):
        """Test --max-pdu overrides default PDU size [Category A]

        Verify association succeeds with custom PDU size.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--max-pdu",
            "4096",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"max-pdu failed: {result.stderr}"
        _assert_log_has_events(result)
        text = _combined_text(result, result.scan_log)
        assert any(x in text for x in ["echo", "association", "mock_pacs", "dicom"]), (
            f"Expected successful DICOM association with custom PDU: {text[:500]}"
        )

    # ========================================================================
    # Category B: Conditional tests (accept rc 0 or 1, validate if successful)
    # ========================================================================

    def test_dump_all_bulk_export(self, cli_runner, target, port, tmp_path):
        """Test --dump-all with patient/study limits [Category B]"""
        output_dir = tmp_path / "dicom_export"
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--dump-all",
            "--max-patients",
            "1",
            "--max-studies",
            "2",
            "--output-dir",
            str(output_dir),
            json_log=True,
            timeout=45,
            expect_json=False,
        )

        assert result.returncode in [0, 1], f"dump-all crashed: rc={result.returncode}"
        text = _combined_text(result, result.scan_log if result.scan_log else None)
        assert any(x in text for x in ["enumerating", "patients", "export", "bulk", "recursive"]), (
            f"Expected bulk export progress output: {text[:500]}"
        )

    def test_c_get_retrieve(self, cli_runner, target, port):
        """Test --get (C-GET) with study UID [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--get",
            "--study-uid",
            MOCK_STUDY_UID,
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.returncode in [0, 1], f"C-GET crashed: rc={result.returncode}"
        text = _combined_text(result, result.scan_log if result.scan_log else None)
        assert any(x in text for x in ["retriev", "c-get", "image", "dicom"]), (
            f"Expected retrieval output from C-GET: {text[:500]}"
        )

    def test_c_move_transfer(self, cli_runner, target, port):
        """Test --move with --dest-aet for C-MOVE [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--move",
            "--dest-aet",
            "MOCK_PACS",
            "--study-uid",
            MOCK_STUDY_UID,
            "--confirm",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.returncode in [0, 1], f"C-MOVE crashed: rc={result.returncode}"
        text = _combined_text(result, result.scan_log if result.scan_log else None)
        # With --confirm the gate is cleared; the scanner must actually issue the
        # C-MOVE (not just print the confirm-required notice).
        assert "c-move" in text or "transfer" in text, (
            f"Expected C-MOVE transfer output: {text[:500]}"
        )
        assert "requires --confirm" not in text, (
            f"C-MOVE should run with --confirm, not bail on the gate: {text[:500]}"
        )

    def test_c_store_missing_file(self, cli_runner, target, port):
        """Test --store --store-file with nonexistent file handles gracefully [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--store",
            "--store-file",
            "/nonexistent/file.dcm",
            "--confirm",
            format="json",
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1, 2], "C-STORE should handle missing file gracefully"
        text = _combined_text(result, result.scan_log if result.scan_log else None)
        # With --confirm the gate is cleared, so the scanner reaches the file
        # loading step and must report the missing file (not the confirm notice).
        assert "requires --confirm" not in text, (
            f"C-STORE should run with --confirm, not bail on the gate: {text[:500]}"
        )
        assert any(
            x in text for x in ["no dicom files", "not found", "no such file", "error", "fail"]
        ), f"Expected error message about missing file: {text[:500]}"

    def test_c_store_dir_uploads_files(self, cli_runner, target, port, tmp_path):
        """Test --store --store-dir uploads every .dcm file found in a directory [Category A]"""
        pytest.importorskip("pydicom")
        from pydicom.dataset import Dataset, FileMetaDataset
        from pydicom.uid import CTImageStorage, ExplicitVRLittleEndian, generate_uid

        store_dir = tmp_path / "store_dir"
        store_dir.mkdir()

        for i in range(2):
            file_meta = FileMetaDataset()
            file_meta.MediaStorageSOPClassUID = CTImageStorage
            file_meta.MediaStorageSOPInstanceUID = generate_uid()
            file_meta.TransferSyntaxUID = ExplicitVRLittleEndian

            ds = Dataset()
            ds.file_meta = file_meta
            ds.is_little_endian = True
            ds.is_implicit_VR = False
            ds.SOPClassUID = CTImageStorage
            ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
            ds.PatientName = f"TEST^STOREDIR{i}"
            ds.PatientID = f"STOREDIRTEST{i}"
            ds.Modality = "CT"
            ds.StudyInstanceUID = generate_uid()
            ds.SeriesInstanceUID = generate_uid()

            ds.save_as(str(store_dir / f"image_{i}.dcm"), enforce_file_format=True)

        # A non-.dcm file in the same directory must be ignored by the glob.
        (store_dir / "readme.txt").write_text("not a dicom file")

        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--store",
            "--store-dir",
            str(store_dir),
            "--confirm",
            format="json",
            json_log=True,
            timeout=20,
        )

        assert result.returncode in [0, 1], f"C-STORE --store-dir crashed: rc={result.returncode}"
        text = _combined_text(result, result.scan_log if result.scan_log else None)
        assert "requires --confirm" not in text, (
            f"C-STORE should run with --confirm, not bail on the gate: {text[:500]}"
        )
        # Exactly the two .dcm files must be picked up -- readme.txt excluded.
        assert "uploading 2 dicom file" in text, (
            f"Expected scanner to find exactly 2 .dcm files from --store-dir: {text[:500]}"
        )
        assert "uploaded: image_" in text, (
            f"Expected at least one successful upload from --store-dir: {text[:500]}"
        )

    def test_brute_ae_strict_server(self, cli_runner, mock_host, mock_ports):
        """Test --aet-brute against strict server (AET whitelist) [Category B]"""
        strict_port = mock_ports.get("dicom_strict", 11113)

        require_port(mock_host, strict_port, "DICOM strict server", timeout=3)

        result = cli_runner.run(
            self.protocol_name,
            mock_host,
            "--port",
            str(strict_port),
            "--aet-brute",
            "--confirm",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.returncode in [0, 1], (
            f"AET brute force (strict) crashed: rc={result.returncode}"
        )
        text = _combined_text(result, result.scan_log if result.scan_log else None)
        # With --confirm the gate is cleared; the brute-force must actually run
        # and emit its per-target testing/results banner (not the confirm notice).
        assert "requires --confirm" not in text, (
            f"Strict brute should run with --confirm, not bail on the gate: {text[:500]}"
        )
        assert "testing" in text and "ae titles" in text, (
            f"Expected brute-force to test the AE Title wordlist: {text[:500]}"
        )
        # The scanner must report a structured tally of valid vs rejected AETs.
        assert "valid ae titles:" in text and "rejected:" in text, (
            f"Expected brute-force valid/rejected tally: {text[:500]}"
        )

    @pytest.mark.security
    def test_tls_connection(self, cli_runner, target, port):
        """Test --tls connection attempt [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--tls",
            format="json",
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1], f"TLS connection crashed: rc={result.returncode}"
        text = _combined_text(result, result.scan_log if result.scan_log else None)
        assert any(
            x in text for x in ["tls", "ssl", "encrypt", "secure", "handshake", "association"]
        ), f"Expected TLS-related output: {text[:500]}"

    def test_dead_scan_mode_flags_are_rejected(self, cli_runner, target, port):
        """--discover/--quick/--deep-scan are no longer accepted [Category C]

        These were parsed but never read by the DICOM runner, so each one ran the
        same default scan. The tests that used to live here asserted only that
        C-ECHO output appeared -- which it did for a plain scan too, so they would
        have passed even if the flags were deleted.

        --full is not checked here: it is an unambiguous abbreviation of the global
        --full-width, so argparse still absorbs it.
        """
        for flag in ("--discover", "--quick", "--deep-scan"):
            result = cli_runner.run(self.protocol_name, target, "--port", str(port), flag)
            assert result.returncode == 2, f"{flag} should be rejected by argparse"
            assert "unrecognized arguments" in (result.stderr or ""), (
                f"{flag} should be reported as unrecognized, got: {result.stderr!r}"
            )

    # ========================================================================
    # Category C: Error handling (assert doesn't crash)
    # ========================================================================

    def test_c_find_image_level(self, cli_runner, target, port):
        """Test C-FIND at IMAGE level without --series-uid [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--find",
            "--query-level",
            "IMAGE",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.returncode in [0, 1], f"IMAGE query crashed: rc={result.returncode}"
        text = _combined_text(result, result.scan_log if result.scan_log else None)
        assert "series" in text or "image" in text or "requires" in text, (
            f"Expected error about missing --series-uid for IMAGE level: {text[:500]}"
        )

    def test_worklist_query(self, cli_runner, target, port):
        """Test --worklist queries MWL [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--worklist",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.returncode in [0, 1], f"worklist crashed: rc={result.returncode}"
        text = _combined_text(result, result.scan_log if result.scan_log else None)
        assert any(
            x in text for x in ["worklist", "scheduled", "procedure", "fail", "error", "no", "0"]
        ), f"Expected worklist query attempt output: {text[:500]}"

    def test_worklist_modality_filter(self, cli_runner, target, port):
        """Test --worklist with --worklist-modality filter [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--worklist",
            "--worklist-modality",
            "CT",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.returncode in [0, 1], (
            f"worklist modality filter crashed: rc={result.returncode}"
        )
        text = _combined_text(result, result.scan_log if result.scan_log else None)
        assert any(
            x in text for x in ["worklist", "mwl", "fail", "error", "scheduled", "not supported"]
        ), f"Expected worklist attempt or error output: {text[:500]}"

    def test_worklist_date_filter(self, cli_runner, target, port):
        """Test --worklist with --worklist-date filter [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--worklist",
            "--worklist-date",
            "20250130",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.returncode in [0, 1], f"worklist date filter crashed: rc={result.returncode}"
        text = _combined_text(result, result.scan_log if result.scan_log else None)
        assert any(
            x in text for x in ["worklist", "mwl", "fail", "error", "scheduled", "not supported"]
        ), f"Expected worklist attempt or error output: {text[:500]}"

    def test_worklist_station_filter(self, cli_runner, target, port):
        """Test --worklist with --worklist-station filter [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--worklist",
            "--worklist-station",
            "CT_SCANNER_01",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.returncode in [0, 1], (
            f"worklist station filter crashed: rc={result.returncode}"
        )
        text = _combined_text(result, result.scan_log if result.scan_log else None)
        assert any(
            x in text for x in ["worklist", "mwl", "fail", "error", "scheduled", "not supported"]
        ), f"Expected worklist attempt or error output: {text[:500]}"

    @pytest.mark.fuzz
    def test_fuzz_requires_confirm(self, cli_runner, target, port):
        """Test that --fuzz without --confirm warns/refuses [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--fuzz",
            format="json",
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1], f"Fuzz without confirm crashed: rc={result.returncode}"
        text = _combined_text(result, result.scan_log if result.scan_log else None)
        assert any(x in text for x in ["confirm", "requires --confirm", "dangerous"]), (
            f"Expected warning about missing --confirm for fuzz: {text[:500]}"
        )

    @pytest.mark.fuzz
    @pytest.mark.slow
    def test_fuzz_with_confirm(self, cli_runner, target, port):
        """Test --fuzz --confirm with limited iterations [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--fuzz",
            "--confirm",
            "--fuzz-iterations",
            "3",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.returncode in [0, 1], f"Fuzzing crashed: rc={result.returncode}"
        text = _combined_text(result, result.scan_log if result.scan_log else None)
        assert any(x in text for x in ["fuzz", "iteration", "fuzzing", "mutation"]), (
            f"Expected fuzzing output: {text[:500]}"
        )

    def test_common_ae_titles(self, cli_runner, target, port):
        """Test --common-ae triggers brute force with vendor defaults [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--common-ae",
            "--confirm",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"--common-ae failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        text = _combined_text(result, log)
        assert "brute force" in text or "valid" in text, (
            f"Expected brute force results from --common-ae: {text[:500]}"
        )
        # --common-ae uses the built-in vendor AE Title list; the scanner
        # announces how many common AETs it is testing.
        assert "common vendor ae titles" in text or "ae titles against" in text, (
            f"--common-ae should test the built-in vendor AE Title list: {text[:500]}"
        )

    def test_ae_wordlist_custom_file(self, cli_runner, target, port, tmp_path):
        """Test --ae-wordlist loads AE Titles from a custom file [Category A]"""
        # Create a small custom wordlist
        wordlist = tmp_path / "custom_aets.txt"
        wordlist.write_text("# Custom AET wordlist\nOIDA_TEST\nMOCK_PACS\nSCU_TEST\n")

        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--aet-brute",
            "--ae-wordlist",
            str(wordlist),
            "--confirm",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"--ae-wordlist failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        text = _combined_text(result, log)
        assert "brute force" in text or "valid" in text or "wordlist" in text, (
            f"Expected brute force results from custom wordlist: {text[:500]}"
        )
        # The custom wordlist must actually be loaded (not the built-in default):
        # the scanner echoes the wordlist source path it loaded from.
        assert str(wordlist).lower() in text or "custom_aets.txt" in text, (
            f"Scanner should report loading the custom wordlist file: {text[:500]}"
        )

    # ========================================================================
    # Inherited test overrides (add return code assertions to base class tests)
    # ========================================================================

    def test_json_output_format(self, cli_runner, target, port):
        """Verify JSON output is properly formatted [Category A]"""
        args = [self.protocol_name, target] + self._get_port_args(port)
        result = cli_runner.run(*args, format="json")

        assert result.returncode == 0, f"JSON output test failed: rc={result.returncode}"
        if result.json_output:
            self._validate_json_output(result.json_output)

    def test_connection_refused(self, cli_runner):
        """Test handling of connection refused error [Category C]"""
        target = self.get_target("127.0.0.1", 65534)
        args = [self.protocol_name, target] + self._get_port_args(65534)
        result = cli_runner.run(
            *args,
            "--timeout",
            "3",
            timeout=10,
            expect_json=False,
        )

        assert result.returncode != -1, "Command should not hang"
        assert result.returncode in [0, 1], (
            f"Connection refused should be handled gracefully, got rc={result.returncode}"
        )

    def test_timeout_handling(self, cli_runner):
        """Test timeout is properly enforced [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            self.get_target("10.255.255.1"),
            "--timeout",
            "3",
            timeout=15,
            expect_json=False,
        )

        assert result.returncode != -1, "Command should not hang on timeout"
        assert result.execution_time < 20, "Command did not respect timeout"

    @pytest.mark.slow
    def test_concurrent_connections(self, cli_runner, target, port):
        """Test multiple concurrent connections to same target [Category B]"""
        import concurrent.futures

        port_args = self._get_port_args(port)

        def run_scan():
            args = [self.protocol_name, target] + port_args
            return cli_runner.run(*args, format="json", timeout=45)

        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(run_scan) for _ in range(3)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        for i, r in enumerate(results):
            assert r.returncode != -1, f"Concurrent connection {i} timed out"
            assert r.returncode in [0, 1], f"Concurrent connection {i} crashed: rc={r.returncode}"
        successes = [r for r in results if r.success]
        assert len(successes) >= 1, "No concurrent connections succeeded"

    def test_verbose_output(self, cli_runner, target, port):
        """Test verbose output flag [Category B]"""
        args = [self.protocol_name, target] + self._get_port_args(port) + ["-v"]
        result = cli_runner.run(*args, expect_json=False)

        assert result.returncode in [0, 1, 2], f"Verbose mode crashed: rc={result.returncode}"
        assert result.stdout or result.stderr, "No output with verbose flag"

    def test_debug_output(self, cli_runner, target, port):
        """Test debug output flag [Category B]"""
        args = [self.protocol_name, target] + self._get_port_args(port) + ["--debug"]
        result = cli_runner.run(*args, expect_json=False)

        assert result.returncode in [0, 1, 2], f"Debug mode crashed: rc={result.returncode}"

    # ========================================================================
    # Security Finding Tests
    # ========================================================================
    # Tests for every security_finding() call in the DICOM scanner.
    # Source: src/oida/protocols/dicom/__init__.py lines 1041-2492
    #
    # Finding inventory (15 calls, 13 unique titles):
    #   1. "No encryption"               line 1986  _analyze_security  always fires without --tls
    #   2. "Weak AET whitelist"           line 1938  _analyze_security  fires with default AET "OIDA"
    #   3. "No authentication"            line 1041  _aet_brute_force   >5 valid or "ANY"/"*"
    #   4. "Permissive AET policy"        line 1947  _analyze_security  >5 valid AETs after brute
    #   5. "Unrestricted query access"    line 1155  _cfind_query       wildcard + results > 0
    #   6. "Unrestricted query access"    line 1955  _analyze_security  duplicate of above
    #   7. "Mass data exfiltration"       line 1535  _recursive_bulk    images > 0
    #   8. "Bulk image retrieval"         line 1602  _cget_retrieve     files > 0
    #   9. "Unrestricted image retrieval" line 1963  _analyze_security  cget files > 0
    #  10. "Unrestricted upload"          line 1672  _cstore_send       uploads > 0
    #  11. "Unrestricted upload"          line 1971  _analyze_security  duplicate of above
    #  12. "Open transfer"               line 1748  _cmove_request     completed > 0
    #  13. "Open transfer policy"         line 1979  _analyze_security  cmove completed > 0
    #  14. "Unrestricted worklist access" line 2492  _worklist_query    count > 0 + no filters
    # ========================================================================

    @pytest.mark.security
    def test_finding_no_encryption(self, cli_runner, target, port):
        """Test 'No encryption' finding fires on plaintext connection [Category A]

        _analyze_security() emits "No encryption" whenever --tls is not used.
        This is the most basic security finding and always fires on the mock.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"Basic connection failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        security = log.get_security_findings()
        assert len(security) >= 1, (
            f"Expected at least 1 security finding (No encryption), got {len(security)}"
        )

        # Use assert_security_finding for exact match on data.finding
        log.assert_security_finding("No encryption")

        # Validate the finding detail text mentions plaintext/PHI.
        # security_finding(title, detail=...) stores the description in data.details.
        no_enc_findings = [
            f for f in security if f.get("data", {}).get("finding") == "No encryption"
        ]
        detail = no_enc_findings[0].get("data", {}).get("details", "")
        assert "plaintext" in detail.lower() or "phi" in detail.lower(), (
            f"'No encryption' finding detail should mention 'plaintext' or 'PHI', got: {detail!r}"
        )

    @pytest.mark.security
    def test_finding_no_encryption_absent_with_tls(self, cli_runner, target, port):
        """Test 'No encryption' finding does NOT fire when --tls is used [Category B]

        When --tls is specified, _analyze_security() skips the "No encryption" finding.
        The connection itself may fail (mock may not support TLS), but the finding
        should not appear.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--tls",
            format="json",
            json_log=True,
            timeout=15,
        )

        # TLS may fail (mock doesn't serve TLS on standard port) -- that's okay
        assert result.returncode in [0, 1], f"TLS attempt crashed: rc={result.returncode}"

        # If we got a scan_log, verify "No encryption" is NOT present
        text = _combined_text(result, result.scan_log if result.scan_log else None)
        assert any(x in text for x in ["tls", "ssl", "encrypt", "association", "dicom"]), (
            f"Expected TLS-related output: {text[:500]}"
        )

        if result.scan_log:
            security = result.scan_log.get_security_findings()
            no_enc = [f for f in security if f.get("data", {}).get("finding") == "No encryption"]
            assert len(no_enc) == 0, "When --tls is used, 'No encryption' finding should NOT appear"

    @pytest.mark.security
    def test_finding_weak_aet_whitelist(self, cli_runner, target, port):
        """Test 'Weak AET whitelist' finding fires with default AET 'OIDA' [Category A]

        _analyze_security() checks if self.calling_aet is in ["ANY", "*", "ANYSCU", "OIDA"].
        Since the default AET is "OIDA", this finding should always fire on
        a successful connection without a custom --aet.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"Connection failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        log.assert_security_finding("Weak AET whitelist")

        # Validate detail mentions the AE Title "OIDA".
        # security_finding(title, detail=...) stores the description in data.details.
        findings = [
            f
            for f in log.get_security_findings()
            if f.get("data", {}).get("finding") == "Weak AET whitelist"
        ]
        detail = findings[0].get("data", {}).get("details", "")
        assert "oida" in detail.lower(), (
            f"'Weak AET whitelist' finding should mention AET name 'OIDA', got: {detail!r}"
        )

    @pytest.mark.security
    def test_finding_weak_aet_whitelist_absent_with_custom_aet(self, cli_runner, target, port):
        """Test 'Weak AET whitelist' does NOT fire with a non-default AET [Category A]

        When --aet is set to a custom value not in the weak list
        ["ANY", "*", "ANYSCU", "OIDA"], the finding should not fire.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--aet",
            "SECURE_SCANNER",
            "--called-aet",
            "MOCK_PACS",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"Custom AET connection failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        security = log.get_security_findings()
        weak_findings = [
            f for f in security if f.get("data", {}).get("finding") == "Weak AET whitelist"
        ]
        assert len(weak_findings) == 0, (
            "With --aet SECURE_SCANNER, 'Weak AET whitelist' should NOT fire. "
            f"Found: {[f.get('data', {}).get('details') for f in weak_findings]}"
        )

    @pytest.mark.security
    def test_finding_unrestricted_query_access(self, cli_runner, target, port):
        """Test 'Unrestricted query access' fires on wildcard C-FIND [Category A]

        When --find uses patient_name="*" (default) and results > 0,
        the scanner emits "Unrestricted query access" with PHI exposure detail.
        The mock has 5 patients, so wildcard always returns results.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--find",
            "--patient-name",
            "*",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"Wildcard C-FIND failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        log.assert_security_finding("Unrestricted query access")

        # Validate detail mentions patient records / PHI.
        # security_finding(title, detail=...) stores the description in data.details.
        findings = [
            f
            for f in log.get_security_findings()
            if f.get("data", {}).get("finding") == "Unrestricted query access"
        ]
        assert len(findings) >= 1, "Expected at least 1 'Unrestricted query access' finding"
        detail = findings[0].get("data", {}).get("details", "")
        assert "patient" in detail.lower() or "record" in detail.lower(), (
            f"'Unrestricted query access' detail should mention 'patient' or 'record', "
            f"got: {detail!r}"
        )

    @pytest.mark.security
    def test_finding_unrestricted_query_absent_with_specific_filter(self, cli_runner, target, port):
        """Test 'Unrestricted query access' does NOT fire with specific patient filter [Category A]

        When --patient-name is set to a specific name (not "*"), the wildcard
        query check in _cfind_query is skipped.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--find",
            "--patient-name",
            "DOE*",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"Filtered C-FIND failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        security = log.get_security_findings()
        unrestricted = [
            f for f in security if f.get("data", {}).get("finding") == "Unrestricted query access"
        ]
        assert len(unrestricted) == 0, (
            "With --patient-name DOE*, 'Unrestricted query access' should NOT fire "
            f"(only fires on wildcard '*'). Found: {unrestricted}"
        )

    @pytest.mark.security
    def test_finding_no_authentication_aet_brute(self, cli_runner, target, port):
        """Test 'No authentication' fires during AET brute force on open server [Category A]

        When --aet-brute runs against the open mock (port 11112, no whitelist),
        the server accepts ALL AE Titles. Since >5 are valid, the scanner emits
        "No authentication" with detail about weak AET whitelist.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--aet-brute",
            "--confirm",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"AET brute force failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        log.assert_security_finding("No authentication")

        findings = [
            f
            for f in log.get_security_findings()
            if f.get("data", {}).get("finding") == "No authentication"
        ]
        # security_finding(title, detail=...) stores the description in
        # data.details (the category slot stays empty for this finding).
        detail = findings[0].get("data", {}).get("details", "")
        assert (
            "aet" in detail.lower() or "ae title" in detail.lower() or "whitelist" in detail.lower()
        ), f"'No authentication' detail should mention AET/whitelist, got: {detail!r}"

    @pytest.mark.security
    def test_finding_permissive_aet_policy(self, cli_runner, target, port):
        """Test 'Permissive AET policy' behavior during AET brute force [Category B]

        _analyze_security() checks AET brute results for >5 valid AETs and
        emits "Permissive AET policy". However, _aet_brute_force() returns
        early (proto_flow line 399) BEFORE _analyze_security() runs, so
        this finding only fires if the scanner reaches _analyze_security.

        This test validates the brute force ran and checks for the finding
        only if _analyze_security was reached.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--aet-brute",
            "--confirm",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.returncode in [0, 1], f"AET brute force crashed: rc={result.returncode}"
        # Unconditional: scanner must actually run the brute force (with --confirm
        # the gate is cleared, so the testing/results banner must appear).
        text = _combined_text(result, result.scan_log if result.scan_log else None)
        assert "testing" in text or "brute force results" in text, (
            f"Expected brute force to run and report results: {text[:500]}"
        )

        # Conditional: if _analyze_security ran, check for the finding detail
        if result.scan_log:
            security = result.scan_log.get_security_findings()
            permissive = [
                f for f in security if f.get("data", {}).get("finding") == "Permissive AET policy"
            ]
            if permissive:
                detail = permissive[0].get("data", {}).get("details", "")
                assert "ae title" in detail.lower() or "accept" in detail.lower(), (
                    f"'Permissive AET policy' detail should mention AE Titles, got: {detail!r}"
                )

    @pytest.mark.security
    def test_finding_bulk_image_retrieval_cget(self, cli_runner, target, port, tmp_path):
        """Test 'Bulk image retrieval' fires during C-GET [Category B]

        When --get retrieves files, _cget_retrieve() emits "Bulk image retrieval".
        The mock supports C-GET and returns instances for known study UIDs.
        """
        output_dir = tmp_path / "cget_output"
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--get",
            "--study-uid",
            MOCK_STUDY_UID,
            "--output-dir",
            str(output_dir),
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.returncode in [0, 1], f"C-GET crashed: rc={result.returncode}"
        text = _combined_text(result, result.scan_log if result.scan_log else None)
        assert any(x in text for x in ["retriev", "c-get", "image", "dicom"]), (
            f"Expected C-GET attempt output: {text[:500]}"
        )

        # If C-GET succeeded and retrieved files, the finding should appear
        if result.scan_log:
            security = result.scan_log.get_security_findings()
            bulk_findings = [
                f
                for f in security
                if f.get("data", {}).get("finding")
                in [
                    "Bulk image retrieval",
                    "Unrestricted image retrieval",
                ]
            ]
            if result.success and bulk_findings:
                # security_finding(title, detail=...) stores description in data.details.
                detail = bulk_findings[0].get("data", {}).get("details", "")
                assert "image" in detail.lower() or "retriev" in detail.lower(), (
                    f"Bulk/unrestricted retrieval finding should mention images, got: {detail!r}"
                )

    @pytest.mark.security
    def test_finding_open_transfer_cmove(self, cli_runner, target, port):
        """Test 'Open transfer' / 'Open transfer policy' fires during C-MOVE [Category B]

        When --move transfers images, _cmove_request() emits "Open transfer"
        and _analyze_security() emits "Open transfer policy".
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--move",
            "--dest-aet",
            "MOCK_PACS",
            "--study-uid",
            MOCK_STUDY_UID,
            "--confirm",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.returncode in [0, 1], f"C-MOVE crashed: rc={result.returncode}"
        text = _combined_text(result, result.scan_log if result.scan_log else None)
        assert any(x in text for x in ["transfer", "c-move", "mock_pacs", "requesting"]), (
            f"Expected C-MOVE attempt output: {text[:500]}"
        )

        # If C-MOVE succeeded and transferred images, findings should appear
        if result.scan_log:
            security = result.scan_log.get_security_findings()
            transfer_findings = [
                f
                for f in security
                if f.get("data", {}).get("finding")
                in [
                    "Open transfer",
                    "Open transfer policy",
                ]
            ]
            if result.success and transfer_findings:
                # security_finding(title, detail=...) stores description in data.details.
                detail = transfer_findings[0].get("data", {}).get("details", "")
                assert "transfer" in detail.lower() or "image" in detail.lower(), (
                    f"Open transfer finding detail should mention transfer/images, got: {detail!r}"
                )

    @pytest.mark.security
    def test_finding_mass_data_exfiltration_dump_all(self, cli_runner, target, port, tmp_path):
        """Test 'Mass data exfiltration' fires during --dump-all [Category B]

        When --dump-all exports images, _recursive_bulk_export() emits
        "Mass data exfiltration" with patient/image counts.
        """
        output_dir = tmp_path / "dump_all_security"
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--dump-all",
            "--max-patients",
            "1",
            "--max-studies",
            "1",
            "--output-dir",
            str(output_dir),
            json_log=True,
            timeout=45,
            expect_json=False,
        )

        assert result.returncode in [0, 1], f"dump-all crashed: rc={result.returncode}"
        text = _combined_text(result, result.scan_log if result.scan_log else None)
        assert any(x in text for x in ["enumerating", "patients", "export", "bulk", "recursive"]), (
            f"Expected bulk export attempt output: {text[:500]}"
        )

        # If dump-all retrieved images, finding should fire
        if result.scan_log:
            security = result.scan_log.get_security_findings()
            exfil_findings = [
                f for f in security if f.get("data", {}).get("finding") == "Mass data exfiltration"
            ]
            if result.success and exfil_findings:
                # security_finding(title, detail=...) stores description in data.details.
                detail = exfil_findings[0].get("data", {}).get("details", "")
                assert (
                    "image" in detail.lower()
                    or "export" in detail.lower()
                    or "patient" in detail.lower()
                ), (
                    f"'Mass data exfiltration' detail should mention images/patients, got: {detail!r}"
                )

    @pytest.mark.security
    def test_finding_unrestricted_worklist_access(self, cli_runner, target, port):
        """Test 'Unrestricted worklist access' behavior on worklist query [Category C]

        The mock does NOT support ModalityWorklistInformationFind (MWL),
        so --worklist will fail gracefully. The "Unrestricted worklist access"
        finding (line 2492) only fires if count > 0 with no filters, which
        requires MWL support. This test verifies the scanner handles the
        failure without crashing and does NOT emit the finding.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--worklist",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.returncode in [0, 1], f"Worklist query crashed: rc={result.returncode}"
        text = _combined_text(result, result.scan_log if result.scan_log else None)
        assert any(
            x in text for x in ["worklist", "mwl", "fail", "error", "not supported", "no", "0"]
        ), f"Expected worklist attempt output: {text[:500]}"

        # Since MWL is not supported, finding should NOT appear
        if result.scan_log:
            security = result.scan_log.get_security_findings()
            worklist_findings = [
                f
                for f in security
                if f.get("data", {}).get("finding") == "Unrestricted worklist access"
            ]
            assert len(worklist_findings) == 0, (
                "'Unrestricted worklist access' should NOT fire when MWL is unsupported. "
                f"Found: {worklist_findings}"
            )

    @pytest.mark.security
    def test_finding_multiple_findings_on_basic_scan(self, cli_runner, target, port):
        """Test that basic scan produces expected combination of findings [Category A]

        A basic scan (no --tls, default AET "OIDA") should produce at minimum:
        - "No encryption" (always fires without --tls)
        - "Weak AET whitelist" (fires because default AET is "OIDA")
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"Basic scan failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        security = log.get_security_findings()
        finding_titles = [f.get("data", {}).get("finding", "") for f in security]

        assert "No encryption" in finding_titles, (
            f"Basic scan must produce 'No encryption'. Got findings: {finding_titles}"
        )
        assert "Weak AET whitelist" in finding_titles, (
            f"Basic scan with default AET must produce 'Weak AET whitelist'. "
            f"Got findings: {finding_titles}"
        )

    @pytest.mark.security
    def test_finding_cfind_wildcard_produces_dual_findings(self, cli_runner, target, port):
        """Test wildcard C-FIND produces query finding from both code paths [Category A]

        The "Unrestricted query access" finding fires from two locations:
        1. _cfind_query() line 1155 (during query execution)
        2. _analyze_security() line 1955 (during post-scan analysis)

        Both should fire when --find --patient-name "*" returns results.
        The mock returns 5 patients, so results > 0 is guaranteed.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--find",
            "--patient-name",
            "*",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"Wildcard C-FIND failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        security = log.get_security_findings()
        query_findings = [
            f for f in security if f.get("data", {}).get("finding") == "Unrestricted query access"
        ]

        # At least one "Unrestricted query access" finding must be present
        assert len(query_findings) >= 1, (
            f"Expected at least 1 'Unrestricted query access' finding. "
            f"All findings: {[f.get('data', {}).get('finding') for f in security]}"
        )

        # Validate that the detail text mentions the patient count.
        # security_finding(title, detail=...) stores description in data.details.
        for finding in query_findings:
            detail = finding.get("data", {}).get("details", "")
            assert "patient" in detail.lower() or "record" in detail.lower(), (
                f"Finding detail should reference patients/records, got: {detail!r}"
            )

    @pytest.mark.security
    def test_finding_aet_brute_all_findings(self, cli_runner, target, port):
        """Test AET brute force on open server produces full security finding set [Category A]

        On the open mock (no AET whitelist), --aet-brute should produce:
        - "No authentication" (from _aet_brute_force, >5 valid)
        - "Permissive AET policy" (from _analyze_security, >5 valid)
        - "No encryption" (from _analyze_security, no --tls)

        NOTE: _aet_brute_force() returns early before create_conn_obj() and
        _analyze_security(), so "Permissive AET policy" and "No encryption"
        may not fire. The test validates "No authentication" unconditionally
        and checks the others only if present.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--aet-brute",
            "--confirm",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"AET brute force failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        security = log.get_security_findings()
        finding_titles = [f.get("data", {}).get("finding", "") for f in security]

        # "No authentication" is the primary finding from _aet_brute_force
        assert "No authentication" in finding_titles, (
            f"AET brute on open server must produce 'No authentication'. Got: {finding_titles}"
        )

    @pytest.mark.security
    def test_finding_event_structure_has_required_fields(self, cli_runner, target, port):
        """Test security finding events have correct structure [Category A]

        Each security finding event should have:
        - event_type: "security"
        - data.finding: the finding title string
        - data.details: descriptive detail string
        - timestamp, level, module: standard event fields
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"Connection failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        security = log.get_security_findings()
        assert len(security) >= 1, "Expected at least 1 security finding"

        for i, finding in enumerate(security):
            # event_type must be "security"
            assert finding.get("event_type") == "security", (
                f"Security finding {i} has wrong event_type: {finding.get('event_type')}"
            )
            # data.finding must be a non-empty string
            data = finding.get("data", {})
            assert isinstance(data.get("finding"), str) and data["finding"], (
                f"Security finding {i} missing data.finding: {data}"
            )
            # data.details contains the description text
            # (security_finding(title, detail=...) maps to data.details)
            assert isinstance(data.get("details"), str) and data["details"], (
                f"Security finding {i} missing data.details: {data}"
            )
            # Standard event fields
            assert "timestamp" in finding, f"Security finding {i} missing timestamp"
            assert "module" in finding, f"Security finding {i} missing module"

    # NOTE: --fuzz-pdu / --fuzz-dimse tests were removed - those flags no longer
    # exist on the DICOM CLI (fuzzing is driven by --fuzz, see test_fuzz_*
    # C-FIND coverage above). They were never implemented as PDU/DIMSE modes.


@contextlib.contextmanager
def _dummy_tcp_server():
    """A local TCP server that accepts connections but never speaks DICOM.

    Safety: binds only to 127.0.0.1 on an ephemeral port. It provides a
    "TCP connects but is not a DICOM SCP" target for the connection-1
    false-positive regression below - it never touches a real device or external
    network. Accepted sockets are held open and silent so the A-ASSOCIATE never
    receives an A-ASSOCIATE-AC.
    """
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    port = srv.getsockname()[1]
    stop = threading.Event()
    conns = []

    def _serve():
        srv.settimeout(0.5)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            conns.append(conn)

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        stop.set()
        with contextlib.suppress(OSError):
            srv.close()
        for conn in conns:
            with contextlib.suppress(OSError):
                conn.close()
        thread.join(timeout=2)


@contextlib.contextmanager
def _garbage_tcp_server():
    """A local TCP server that replies with non-DICOM junk and keeps the
    connection open indefinitely (never closes its end).

    Safety: binds only to 127.0.0.1 on an ephemeral port. This reproduces the
    hang regression below: a malformed/wrong-protocol responder that never
    hangs up, which used to make the DICOM association-abort teardown block
    forever on a stuck reader thread.
    """
    junk = bytes(range(256))
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    port = srv.getsockname()[1]
    stop = threading.Event()
    conns = []

    def _handle(conn):
        try:
            conn.sendall(junk)
            conn.settimeout(0.5)
            while not stop.is_set():
                try:
                    data = conn.recv(8192)
                    if not data:
                        break
                    conn.sendall(junk)
                except socket.timeout:
                    continue
        except OSError:
            pass

    def _serve():
        srv.settimeout(0.5)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            conns.append(conn)
            threading.Thread(target=_handle, args=(conn,), daemon=True).start()

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        stop.set()
        with contextlib.suppress(OSError):
            srv.close()
        for conn in conns:
            with contextlib.suppress(OSError):
                conn.close()
        thread.join(timeout=2)


class TestDICOMP1FalsePositiveRegression:
    """Regression guard for the connection-1 false-positive identification bug.

    A bare TCP connect to a port that speaks *something other than DICOM* opens
    the channel but the A-ASSOCIATE request never gets an A-ASSOCIATE-AC. Before
    the fix, proto_flow returned early on a failed association without setting
    success=False, so the base ``NetworkConnection.run()`` defaulted
    success=True and OIDA reported a false-positive DICOM SCP on any open TCP
    port. The fix sets success=False when ``create_conn_obj()`` reports the
    association was not established.

    Safety: targets only a local in-process dummy TCP server bound to 127.0.0.1
    and a closed local port - never a real device or external network.
    """

    def _read_result_payload(self, out_dir, result):
        candidates = sorted(out_dir.glob("*.json"))
        assert candidates, (
            "no JSON result file was written to the output directory; "
            f"combined output: {result.combined_output[:800]}"
        )
        payload = json.loads(candidates[-1].read_text())
        return payload[0] if isinstance(payload, list) else payload

    def test_non_dicom_tcp_port_is_not_a_false_positive(self, cli_runner, tmp_path):
        """A TCP-connectable but non-DICOM port must report success=False."""
        with _dummy_tcp_server() as port:
            out_dir = tmp_path / "p1_non_dicom"
            result = cli_runner.run(
                "dicom",
                "127.0.0.1",
                "--port",
                str(port),
                "--timeout",
                "3",
                format="json",
                output=str(out_dir),
                expect_json=False,
                timeout=45,
            )
            last = self._read_result_payload(out_dir, result)
            assert last["success"] is False, (
                "connection-1 regression: a non-DICOM TCP port was reported as a "
                f"successful DICOM identification. Payload: {last}"
            )

    def test_closed_port_is_not_a_false_positive(self, cli_runner, tmp_path):
        """A closed local port must report success=False (never a phantom SCP)."""
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("127.0.0.1", 0))
        closed_port = probe.getsockname()[1]
        probe.close()

        out_dir = tmp_path / "p1_closed"
        result = cli_runner.run(
            "dicom",
            "127.0.0.1",
            "--port",
            str(closed_port),
            "--timeout",
            "3",
            format="json",
            output=str(out_dir),
            expect_json=False,
            timeout=45,
        )
        last = self._read_result_payload(out_dir, result)
        assert last["success"] is False, (
            "connection-1 regression: a closed port was reported as a successful "
            f"DICOM identification. Payload: {last}"
        )

    def test_garbage_responder_does_not_hang_past_timeout(self, cli_runner, tmp_path):
        """A peer that keeps the socket open and replies with a malformed
        (non-DICOM) PDU must not hang the CLI well past --timeout.

        Regression for: Association.abort() calls DUL.kill(), which joins the
        DUL reader thread; if that thread is blocked in a plain socket.recv()
        with no timeout (because the peer never closes the connection), the
        whole CLI process hung indefinitely even though "Association Aborted"
        had already been logged. Fix: _disconnect() now force-closes the
        transport socket before calling abort()/shutdown(), unblocking the
        reader thread immediately.
        """
        with _garbage_tcp_server() as port:
            out_dir = tmp_path / "hang_regression"
            start = time.monotonic()
            result = cli_runner.run(
                "dicom",
                "127.0.0.1",
                "--port",
                str(port),
                "--timeout",
                "3",
                format="json",
                output=str(out_dir),
                expect_json=False,
                timeout=20,  # generous wall-clock cap; the bug hung past this
            )
            elapsed = time.monotonic() - start
            assert elapsed < 15, (
                "dicom hang regression: CLI took "
                f"{elapsed:.1f}s (--timeout was 3s) against a garbage/malformed "
                f"responder that keeps the connection open. combined_output="
                f"{result.combined_output[:800]}"
            )
            last = self._read_result_payload(out_dir, result)
            assert last["success"] is False, (
                "a garbage/malformed responder was reported as a successful "
                f"DICOM identification. Payload: {last}"
            )
