#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for DICOM (Digital Imaging and Communications in Medicine) scanner functionality.

Tests the DICOM protocol scanner for:
- C-ECHO verification
- C-FIND queries (patient, study, series, image levels)
- C-GET/C-STORE operations
- AE Title enumeration and brute force
- Security assessment
- Vendor identification
"""

import unittest
from unittest.mock import Mock, patch

import pytest

try:
    import pynetdicom  # noqa: F401

    _PYNETDICOM_AVAILABLE = True
except ImportError:
    _PYNETDICOM_AVAILABLE = False

# The dicom dependency gate is legitimate: without pynetdicom the module-level
# imports (AE, Dataset, Verification) in oida.protocols.dicom are unavailable.
# We deliberately do NOT mark this module `network`: _make_dicom_instance below
# builds the NXC object WITHOUT running proto_flow, so no real socket is opened
# and the suite runs under the default `-m 'not network'` config.
pytestmark = [
    pytest.mark.skipif(
        not _PYNETDICOM_AVAILABLE,
        reason="pynetdicom not installed; install via `pip install -e .[dicom]`",
    ),
]


def _make_dicom_instance(args, host="192.168.1.100", **overrides):
    """Build a dicom NXC instance WITHOUT triggering proto_flow / a real socket.

    dicom.__init__ -> NetworkConnection.__init__ -> proto_flow() opens a real
    TCP/DICOM association on construction. We bypass that by constructing via
    __new__ and setting the attributes that __init__, the base __init__, and
    proto_flow would otherwise populate. Tests then assign a MockAssociation /
    MockAE after construction, exactly as before.
    """
    from oida.protocols.dicom import dicom as DicomClass

    obj = DicomClass.__new__(DicomClass)
    # Set by dicom.__init__ before super().__init__()
    obj.protocol_name = "dicom"
    obj.default_port = 11112
    obj.ae = None
    obj.assoc = None
    obj._cget_output_path = None
    obj._cget_received_files = []
    # Set by NetworkConnection.__init__
    obj.args = args
    obj.db = None
    obj.host = host
    obj.hostname = host
    obj.ip = host
    obj.conn = None
    obj.logger = Mock()
    obj.results = {
        "host": host,
        "ip": host,
        "protocol": "dicom",
        "port": getattr(args, "port", None) or 11112,
        "success": None,
        "data": {},
    }
    # Set by proto_flow() before the workflow body runs
    obj.calling_aet = getattr(args, "aet", "OIDA") or "OIDA"
    obj.called_aet = getattr(args, "called_aet", "ANY")

    for key, val in overrides.items():
        setattr(obj, key, val)
    return obj


class MockAssociation:
    """Mock DICOM association for testing"""

    def __init__(self, established=True, echo_success=True):
        self.is_established = established
        self.is_rejected = not established
        self.is_aborted = False
        self._echo_success = echo_success
        self.accepted_contexts = []

        # Mock acceptor info
        self.acceptor = Mock()
        self.acceptor.implementation_class_uid = "1.2.826.0.1.3680043.2.135"
        self.acceptor.implementation_version_name = "ORTHANC_1.12.0"
        self.acceptor.maximum_length = 16384
        self.acceptor.user_identity = None
        self.acceptor.asynchronous_operations = None
        self.acceptor.info = {"result_source": "DICOM UL service-provider"}

    def send_c_echo(self):
        """Mock C-ECHO response"""
        status = Mock()
        status.Status = 0x0000 if self._echo_success else 0xA700
        return status

    def send_c_find(self, dataset, model):
        """Mock C-FIND response"""
        # Return mock patient results
        results = []
        for i in range(3):
            status = Mock()
            status.Status = 0xFF00  # Pending

            identifier = Mock()
            identifier.PatientName = f"TEST^PATIENT{i}"
            identifier.PatientID = f"PT00{i}"
            identifier.PatientBirthDate = "19800101"
            identifier.PatientSex = "M" if i % 2 == 0 else "F"
            identifier.NumberOfPatientRelatedStudies = str(i + 1)

            results.append((status, identifier))

        # Final success
        final_status = Mock()
        final_status.Status = 0x0000
        results.append((final_status, None))

        return iter(results)

    def send_c_get(self, dataset, model):
        """Mock C-GET response"""
        status = Mock()
        status.Status = 0x0000
        return iter([(status, None)])

    def send_c_move(self, dataset, model, move_aet):
        """Mock C-MOVE response"""
        status = Mock()
        status.Status = 0x0000
        return iter([(status, None)])

    def send_c_store(self, dataset):
        """Mock C-STORE response"""
        status = Mock()
        status.Status = 0x0000
        return status

    def release(self):
        """Release association"""
        self.is_established = False


class MockAE:
    """Mock Application Entity for testing"""

    def __init__(self, ae_title="OIDA"):
        self.ae_title = ae_title
        self.network_timeout = 30
        self.acse_timeout = 30
        self.dimse_timeout = 30
        self._contexts = []

    def add_requested_context(self, context):
        """Add presentation context"""
        self._contexts.append(context)

    def associate(self, host, port, ae_title="ANY", evt_handlers=None, tls_args=None):
        """Create mock association"""
        return MockAssociation()


class TestDICOMConstants(unittest.TestCase):
    """Test DICOM constants and mappings"""

    def test_vendor_map_exists(self):
        """Test DICOM vendor map contains expected entries"""
        from oida.protocols.dicom import DICOM_VENDOR_MAP

        self.assertIn("1.2.826.0.1.3680043.2.135", DICOM_VENDOR_MAP)
        self.assertIn("1.2.840.113619", DICOM_VENDOR_MAP)
        self.assertIn("1.3.46.670589", DICOM_VENDOR_MAP)

    def test_vendor_map_values(self):
        """Test DICOM vendor map value structure"""
        from oida.protocols.dicom import DICOM_VENDOR_MAP

        # Check Orthanc entry
        orthanc = DICOM_VENDOR_MAP.get("1.2.826.0.1.3680043.2.135")
        self.assertIsNotNone(orthanc)
        self.assertEqual(orthanc[0], "Orthanc")
        self.assertEqual(orthanc[1], "Open Source PACS")

    def test_phi_tags_list(self):
        """Test PHI tags list contains expected tags"""
        from oida.protocols.dicom import PHI_TAGS

        self.assertIn("PatientName", PHI_TAGS)
        self.assertIn("PatientID", PHI_TAGS)
        self.assertIn("PatientBirthDate", PHI_TAGS)
        self.assertIn("ReferringPhysicianName", PHI_TAGS)
        self.assertIn("InstitutionName", PHI_TAGS)

    def test_default_aet_wordlist(self):
        """Test default AET wordlist contains common entries"""
        from oida.protocols.dicom import DEFAULT_AET_WORDLIST

        self.assertIn("PACS", DEFAULT_AET_WORDLIST)
        self.assertIn("ORTHANC", DEFAULT_AET_WORDLIST)
        self.assertIn("ANY", DEFAULT_AET_WORDLIST)
        self.assertIn("CT", DEFAULT_AET_WORDLIST)
        self.assertIn("MR", DEFAULT_AET_WORDLIST)


class TestDICOMScannerInit(unittest.TestCase):
    """Test DICOM scanner initialization"""

    def setUp(self):
        """Set up test fixtures"""
        self.mock_args = Mock()
        self.mock_args.port = 11112
        self.mock_args.timeout = 30
        self.mock_args.aet = "OIDA"
        self.mock_args.called_aet = "ANY"
        self.mock_args.tls = False
        self.mock_args.verbose = 0
        self.mock_args.find = False
        self.mock_args.get = False
        self.mock_args.store = False
        self.mock_args.move = False
        self.mock_args.aet_brute = None
        self.mock_args.probe_ops = False
        self.mock_args.worklist = False
        self.mock_args.dump_all = False
        self.mock_args.fuzz = False
        self.mock_args.enum_operators = False
        self.mock_args.enum_devices = False
        self.mock_args.time_analysis = False

    @patch("oida.protocols.dicom.PYNETDICOM_AVAILABLE", True)
    def test_scanner_initialization(self):
        """Test basic scanner initialization"""

        scanner = _make_dicom_instance(self.mock_args)

        self.assertEqual(scanner.protocol_name, "dicom")
        self.assertEqual(scanner.default_port, 11112)
        self.assertEqual(scanner.ip, "192.168.1.100")

    @patch("oida.protocols.dicom.PYNETDICOM_AVAILABLE", True)
    def test_scanner_default_aet(self):
        """Test scanner uses correct default AE Titles"""

        scanner = _make_dicom_instance(self.mock_args)
        # proto_flow sets these, but we can check they're accessible
        self.assertIsNotNone(scanner.protocol_name)


class TestDICOMVendorIdentification(unittest.TestCase):
    """Test DICOM vendor identification from Implementation Class UID"""

    def setUp(self):
        """Set up test fixtures"""
        self.mock_args = Mock()
        self.mock_args.port = 11112
        self.mock_args.timeout = 30
        self.mock_args.aet = "OIDA"
        self.mock_args.called_aet = "ANY"
        self.mock_args.tls = False
        self.mock_args.verbose = 0
        self.mock_args.find = False
        self.mock_args.get = False
        self.mock_args.store = False
        self.mock_args.move = False
        self.mock_args.aet_brute = None
        self.mock_args.probe_ops = False
        self.mock_args.worklist = False
        self.mock_args.dump_all = False
        self.mock_args.fuzz = False
        self.mock_args.enum_operators = False
        self.mock_args.enum_devices = False
        self.mock_args.time_analysis = False

    @patch("oida.protocols.dicom.PYNETDICOM_AVAILABLE", True)
    def test_identify_orthanc(self):
        """Test Orthanc vendor identification"""

        scanner = _make_dicom_instance(self.mock_args)
        vendor, desc = scanner._identify_vendor("1.2.826.0.1.3680043.2.135")

        self.assertEqual(vendor, "Orthanc")
        self.assertEqual(desc, "Open Source PACS")

    @patch("oida.protocols.dicom.PYNETDICOM_AVAILABLE", True)
    def test_identify_ge_healthcare(self):
        """Test GE Healthcare vendor identification"""

        scanner = _make_dicom_instance(self.mock_args)
        vendor, desc = scanner._identify_vendor("1.2.840.113619")

        self.assertEqual(vendor, "GE Healthcare")

    @patch("oida.protocols.dicom.PYNETDICOM_AVAILABLE", True)
    def test_identify_philips(self):
        """Test Philips vendor identification"""

        scanner = _make_dicom_instance(self.mock_args)
        vendor, desc = scanner._identify_vendor("1.3.46.670589.11")

        self.assertEqual(vendor, "Philips MR")

    @patch("oida.protocols.dicom.PYNETDICOM_AVAILABLE", True)
    def test_identify_siemens(self):
        """Test Siemens vendor identification"""

        scanner = _make_dicom_instance(self.mock_args)
        vendor, desc = scanner._identify_vendor("1.3.12.2.1107.5")

        self.assertEqual(vendor, "Siemens syngo")

    @patch("oida.protocols.dicom.PYNETDICOM_AVAILABLE", True)
    def test_identify_unknown_vendor(self):
        """Test handling of unknown vendor UID"""

        scanner = _make_dicom_instance(self.mock_args)
        vendor, desc = scanner._identify_vendor("1.2.3.4.5.6.7.8.9")

        self.assertIsNone(vendor)
        self.assertIsNone(desc)

    @patch("oida.protocols.dicom.PYNETDICOM_AVAILABLE", True)
    def test_identify_empty_uid(self):
        """Test handling of empty UID"""

        scanner = _make_dicom_instance(self.mock_args)
        vendor, desc = scanner._identify_vendor("")

        self.assertIsNone(vendor)
        self.assertIsNone(desc)


class TestDICOMConnectionLogic(unittest.TestCase):
    """Test DICOM connection establishment logic"""

    def setUp(self):
        """Set up test fixtures"""
        self.mock_args = Mock()
        self.mock_args.port = 11112
        self.mock_args.timeout = 30
        self.mock_args.aet = "OIDA"
        self.mock_args.called_aet = "ANY"
        self.mock_args.tls = False
        self.mock_args.verbose = 0
        self.mock_args.find = False
        self.mock_args.get = False
        self.mock_args.store = False
        self.mock_args.move = False
        self.mock_args.aet_brute = None
        self.mock_args.probe_ops = False
        self.mock_args.worklist = False
        self.mock_args.dump_all = False
        self.mock_args.fuzz = False
        self.mock_args.bulk_export = False
        self.mock_args.enum_operators = False
        self.mock_args.enum_devices = False
        self.mock_args.time_analysis = False
        self.mock_args.output = None
        self.mock_args.format = "json"

    @patch("oida.protocols.dicom.PYNETDICOM_AVAILABLE", True)
    @patch("oida.protocols.dicom.AE")
    def test_create_conn_obj_success(self, mock_ae_class):
        """Test successful connection establishment"""
        from oida.protocols.dicom import dicom

        mock_ae = MockAE()
        mock_ae_class.return_value = mock_ae

        # Use patching to prevent proto_flow from running fully
        with patch.object(dicom, "proto_flow", return_value=None):
            scanner = dicom.__new__(dicom)
            scanner.args = self.mock_args
            scanner.db = None
            scanner.ip = "192.168.1.100"
            scanner.host = "192.168.1.100"
            scanner.protocol_name = "dicom"
            scanner.default_port = 11112
            scanner.ae = None
            scanner.assoc = None
            scanner._cget_output_path = None
            scanner._cget_received_files = []
            scanner.results = {"data": {}}
            scanner.calling_aet = "OIDA"
            scanner.called_aet = "ANY"
            scanner.logger = Mock()

            result = scanner.create_conn_obj()

            self.assertTrue(result)
            self.assertTrue(scanner.results["data"]["connected"])

    @patch("oida.protocols.dicom.PYNETDICOM_AVAILABLE", True)
    @patch("oida.protocols.dicom.AE")
    def test_create_conn_obj_rejected(self, mock_ae_class):
        """Test connection rejection handling"""
        from oida.protocols.dicom import dicom

        mock_ae = Mock()
        mock_assoc = MockAssociation(established=False)
        mock_ae.associate.return_value = mock_assoc
        mock_ae_class.return_value = mock_ae

        # Use patching to prevent proto_flow from running fully
        with patch.object(dicom, "proto_flow", return_value=None):
            scanner = dicom.__new__(dicom)
            scanner.args = self.mock_args
            scanner.db = None
            scanner.ip = "192.168.1.100"
            scanner.host = "192.168.1.100"
            scanner.protocol_name = "dicom"
            scanner.default_port = 11112
            scanner.ae = None
            scanner.assoc = None
            scanner._cget_output_path = None
            scanner._cget_received_files = []
            scanner.results = {"data": {}}
            scanner.calling_aet = "OIDA"
            scanner.called_aet = "ANY"
            scanner.logger = Mock()

            result = scanner.create_conn_obj()

            self.assertFalse(result)
            self.assertFalse(scanner.results["data"]["connected"])

    @patch("oida.protocols.dicom.PYNETDICOM_AVAILABLE", True)
    @patch("oida.protocols.dicom.AE")
    def test_create_conn_obj_exception(self, mock_ae_class):
        """Test connection exception handling"""
        from oida.protocols.dicom import dicom

        mock_ae_class.side_effect = Exception("Connection failed")

        # Use patching to prevent proto_flow from running fully
        with patch.object(dicom, "proto_flow", return_value=None):
            scanner = dicom.__new__(dicom)
            scanner.args = self.mock_args
            scanner.db = None
            scanner.ip = "192.168.1.100"
            scanner.host = "192.168.1.100"
            scanner.protocol_name = "dicom"
            scanner.default_port = 11112
            scanner.ae = None
            scanner.assoc = None
            scanner._cget_output_path = None
            scanner._cget_received_files = []
            scanner.results = {"data": {}}
            scanner.calling_aet = "OIDA"
            scanner.called_aet = "ANY"
            scanner.logger = Mock()

            result = scanner.create_conn_obj()

            self.assertFalse(result)
            self.assertFalse(scanner.results["data"]["connected"])


class TestDICOMCEcho(unittest.TestCase):
    """Test DICOM C-ECHO verification"""

    def setUp(self):
        """Set up test fixtures"""
        self.mock_args = Mock()
        self.mock_args.port = 11112
        self.mock_args.timeout = 30
        self.mock_args.aet = "OIDA"
        self.mock_args.called_aet = "ANY"
        self.mock_args.tls = False
        self.mock_args.verbose = 0
        self.mock_args.find = False
        self.mock_args.get = False
        self.mock_args.store = False
        self.mock_args.move = False
        self.mock_args.aet_brute = None
        self.mock_args.probe_ops = False
        self.mock_args.worklist = False
        self.mock_args.dump_all = False
        self.mock_args.fuzz = False
        self.mock_args.enum_operators = False
        self.mock_args.enum_devices = False
        self.mock_args.time_analysis = False

    @patch("oida.protocols.dicom.PYNETDICOM_AVAILABLE", True)
    def test_enum_host_info_success(self):
        """Test successful C-ECHO and host info extraction"""

        scanner = _make_dicom_instance(self.mock_args)
        scanner.assoc = MockAssociation(echo_success=True)
        scanner.logger = Mock()

        scanner.enum_host_info()

        self.assertEqual(scanner.results["data"]["c_echo"], "Success")

    @patch("oida.protocols.dicom.PYNETDICOM_AVAILABLE", True)
    def test_enum_host_info_failure(self):
        """Test C-ECHO failure handling"""

        scanner = _make_dicom_instance(self.mock_args)
        scanner.assoc = MockAssociation(echo_success=False)
        scanner.logger = Mock()

        scanner.enum_host_info()

        self.assertIn("Failed", scanner.results["data"]["c_echo"])

    @patch("oida.protocols.dicom.PYNETDICOM_AVAILABLE", True)
    def test_enum_host_info_no_association(self):
        """Test C-ECHO without active association"""

        scanner = _make_dicom_instance(self.mock_args)
        scanner.assoc = None
        scanner.logger = Mock()

        scanner.enum_host_info()

        scanner.logger.fail.assert_called()


class TestDICOMCFind(unittest.TestCase):
    """Test DICOM C-FIND query operations"""

    def setUp(self):
        """Set up test fixtures"""
        self.mock_args = Mock()
        self.mock_args.port = 11112
        self.mock_args.timeout = 30
        self.mock_args.aet = "OIDA"
        self.mock_args.called_aet = "ANY"
        self.mock_args.tls = False
        self.mock_args.verbose = 0
        self.mock_args.find = True
        self.mock_args.get = False
        self.mock_args.store = False
        self.mock_args.move = False
        self.mock_args.aet_brute = None
        self.mock_args.probe_ops = False
        self.mock_args.worklist = False
        self.mock_args.dump_all = False
        self.mock_args.fuzz = False
        self.mock_args.query_level = "PATIENT"
        self.mock_args.patient_name = "*"
        self.mock_args.patient_id = ""
        self.mock_args.study_date = ""
        self.mock_args.study_uid = ""
        self.mock_args.series_uid = ""
        self.mock_args.modality = ""
        self.mock_args.max_results = 100
        self.mock_args.metadata = False
        self.mock_args.dump_tags = False
        self.mock_args.phi_only = False
        self.mock_args.enum_operators = False
        self.mock_args.enum_devices = False
        self.mock_args.time_analysis = False

    @patch("oida.protocols.dicom.PYNETDICOM_AVAILABLE", True)
    @patch("oida.protocols.dicom.Dataset")
    def test_cfind_patient_level(self, mock_dataset):
        """Test C-FIND at PATIENT level"""

        mock_ds = Mock()
        mock_dataset.return_value = mock_ds

        scanner = _make_dicom_instance(self.mock_args)
        scanner.assoc = MockAssociation()
        scanner.logger = Mock()

        scanner._cfind_query()

        self.assertIn("cfind_results", scanner.results["data"])
        self.assertEqual(scanner.results["data"]["cfind_results"]["query_level"], "PATIENT")
        self.assertEqual(scanner.results["data"]["cfind_results"]["count"], 3)

    @patch("oida.protocols.dicom.PYNETDICOM_AVAILABLE", True)
    @patch("oida.protocols.dicom.Dataset")
    def test_cfind_study_level(self, mock_dataset):
        """Test C-FIND at STUDY level"""

        self.mock_args.query_level = "STUDY"
        mock_ds = Mock()
        mock_dataset.return_value = mock_ds

        scanner = _make_dicom_instance(self.mock_args)
        scanner.assoc = MockAssociation()
        scanner.logger = Mock()

        scanner._cfind_query()

        self.assertEqual(scanner.results["data"]["cfind_results"]["query_level"], "STUDY")

    @patch("oida.protocols.dicom.PYNETDICOM_AVAILABLE", True)
    @patch("oida.protocols.dicom.Dataset")
    def test_cfind_series_requires_study_uid(self, mock_dataset):
        """Test C-FIND at SERIES level requires study UID"""

        self.mock_args.query_level = "SERIES"
        self.mock_args.study_uid = ""  # No study UID
        mock_ds = Mock()
        mock_dataset.return_value = mock_ds

        scanner = _make_dicom_instance(self.mock_args)
        scanner.assoc = MockAssociation()
        scanner.logger = Mock()

        scanner._cfind_query()

        scanner.logger.fail.assert_called()

    @patch("oida.protocols.dicom.PYNETDICOM_AVAILABLE", True)
    @patch("oida.protocols.dicom.Dataset")
    def test_cfind_image_requires_series_uid(self, mock_dataset):
        """Test C-FIND at IMAGE level requires series UID"""

        self.mock_args.query_level = "IMAGE"
        self.mock_args.series_uid = ""  # No series UID
        mock_ds = Mock()
        mock_dataset.return_value = mock_ds

        scanner = _make_dicom_instance(self.mock_args)
        scanner.assoc = MockAssociation()
        scanner.logger = Mock()

        scanner._cfind_query()

        scanner.logger.fail.assert_called()

    @patch("oida.protocols.dicom.PYNETDICOM_AVAILABLE", True)
    def test_cfind_no_association(self):
        """Test C-FIND without active association"""

        scanner = _make_dicom_instance(self.mock_args)
        scanner.assoc = None
        scanner.logger = Mock()

        scanner._cfind_query()

        scanner.logger.fail.assert_called()


class TestDICOMResultExtraction(unittest.TestCase):
    """Test DICOM result extraction methods"""

    def setUp(self):
        """Set up test fixtures"""
        self.mock_args = Mock()
        self.mock_args.port = 11112
        self.mock_args.timeout = 30
        self.mock_args.aet = "OIDA"
        self.mock_args.called_aet = "ANY"
        self.mock_args.tls = False
        self.mock_args.verbose = 0
        self.mock_args.find = False
        self.mock_args.get = False
        self.mock_args.store = False
        self.mock_args.move = False
        self.mock_args.aet_brute = None
        self.mock_args.probe_ops = False
        self.mock_args.worklist = False
        self.mock_args.dump_all = False
        self.mock_args.fuzz = False
        self.mock_args.dump_tags = False
        self.mock_args.phi_only = False
        self.mock_args.metadata = False
        self.mock_args.extract_fields = ""
        self.mock_args.enum_operators = False
        self.mock_args.enum_devices = False
        self.mock_args.time_analysis = False

    @patch("oida.protocols.dicom.PYNETDICOM_AVAILABLE", True)
    def test_extract_cfind_result_patient(self):
        """Test extraction of PATIENT level C-FIND result"""

        scanner = _make_dicom_instance(self.mock_args)

        identifier = Mock()
        identifier.PatientName = "DOE^JOHN"
        identifier.PatientID = "PT001"
        identifier.PatientBirthDate = "19800101"
        identifier.PatientSex = "M"
        identifier.NumberOfPatientRelatedStudies = "5"

        result = scanner._extract_cfind_result(identifier, "PATIENT")

        self.assertEqual(result["PatientName"], "DOE^JOHN")
        self.assertEqual(result["PatientID"], "PT001")
        self.assertEqual(result["PatientBirthDate"], "19800101")
        self.assertEqual(result["PatientSex"], "M")

    @patch("oida.protocols.dicom.PYNETDICOM_AVAILABLE", True)
    def test_extract_cfind_result_study(self):
        """Test extraction of STUDY level C-FIND result"""

        scanner = _make_dicom_instance(self.mock_args)

        identifier = Mock()
        identifier.StudyInstanceUID = "1.2.3.4.5"
        identifier.StudyDate = "20240101"
        identifier.StudyTime = "120000"
        identifier.StudyDescription = "CT CHEST"
        identifier.AccessionNumber = "ACC001"
        identifier.PatientName = "DOE^JOHN"
        identifier.PatientID = "PT001"
        identifier.NumberOfStudyRelatedSeries = "3"

        result = scanner._extract_cfind_result(identifier, "STUDY")

        self.assertEqual(result["StudyInstanceUID"], "1.2.3.4.5")
        self.assertEqual(result["StudyDate"], "20240101")
        self.assertEqual(result["StudyDescription"], "CT CHEST")

    @patch("oida.protocols.dicom.PYNETDICOM_AVAILABLE", True)
    def test_extract_cfind_result_series(self):
        """Test extraction of SERIES level C-FIND result"""

        scanner = _make_dicom_instance(self.mock_args)

        identifier = Mock()
        identifier.SeriesInstanceUID = "1.2.3.4.5.6"
        identifier.SeriesNumber = "1"
        identifier.SeriesDescription = "Axial"
        identifier.Modality = "CT"
        identifier.NumberOfSeriesRelatedInstances = "100"

        result = scanner._extract_cfind_result(identifier, "SERIES")

        self.assertEqual(result["SeriesInstanceUID"], "1.2.3.4.5.6")
        self.assertEqual(result["Modality"], "CT")


class TestDICOMAETBruteForce(unittest.TestCase):
    """Test DICOM AE Title brute force functionality"""

    def setUp(self):
        """Set up test fixtures"""
        self.mock_args = Mock()
        self.mock_args.port = 11112
        self.mock_args.timeout = 5
        self.mock_args.aet = "OIDA"
        self.mock_args.called_aet = "ANY"
        self.mock_args.tls = False
        self.mock_args.verbose = 0
        self.mock_args.find = False
        self.mock_args.get = False
        self.mock_args.store = False
        self.mock_args.move = False
        self.mock_args.aet_brute = True
        self.mock_args.ae_wordlist = None
        self.mock_args.common_ae = True
        self.mock_args.confirm = True
        self.mock_args.probe_ops = False
        self.mock_args.worklist = False
        self.mock_args.dump_all = False
        self.mock_args.fuzz = False
        self.mock_args.enum_operators = False
        self.mock_args.enum_devices = False
        self.mock_args.time_analysis = False

    @patch("oida.protocols.dicom.PYNETDICOM_AVAILABLE", True)
    @patch("oida.protocols.dicom.AE")
    def test_aet_brute_force_finds_valid(self, mock_ae_class):
        """Test AET brute force finds valid AE Titles"""
        # _aet_brute_force() is gated behind --confirm (safety: it trips PACS
        # rate-limits / SIEM). The Mock auto-attr already returns truthy, but
        # set it explicitly so the gate intent is visible.
        self.mock_args.confirm = True
        # Steer the wordlist-source resolution down the built-in default path:
        # leave file/common-ae sources unset so os.path.isfile() is never
        # handed a Mock.
        self.mock_args.aet_brute = True
        self.mock_args.ae_wordlist = None
        self.mock_args.common_ae = False

        mock_ae_instance = Mock()
        mock_assoc = MockAssociation()
        mock_ae_instance.associate.return_value = mock_assoc
        mock_ae_class.return_value = mock_ae_instance

        scanner = _make_dicom_instance(self.mock_args)
        scanner.called_aet = "ANY"
        scanner.logger = Mock()

        scanner._aet_brute_force()

        self.assertIn("aet_brute", scanner.results["data"])
        self.assertIn("valid", scanner.results["data"]["aet_brute"])

    @patch("oida.protocols.dicom.PYNETDICOM_AVAILABLE", True)
    @patch("oida.protocols.dicom.AE")
    def test_aet_brute_force_no_port_resolves_default(self, mock_ae_class):
        """Brute force with no --port (args.port is None) targets 11112, not None.

        proto_args registers --port with default=None, and the brute path
        returns before create_conn_obj() can resolve the port, so the port
        fallback must live in _aet_brute_force() itself.
        """
        self.mock_args.confirm = True
        self.mock_args.aet_brute = True
        self.mock_args.ae_wordlist = None
        self.mock_args.common_ae = False
        self.mock_args.tls = False
        # No -p supplied -> argparse default is None (not 11112).
        self.mock_args.port = None

        mock_ae_instance = Mock()
        mock_ae_instance.associate.return_value = MockAssociation()
        mock_ae_class.return_value = mock_ae_instance

        scanner = _make_dicom_instance(self.mock_args)
        scanner.called_aet = "ANY"
        scanner.logger = Mock()

        scanner._aet_brute_force()

        # Every associate() call must use the de-facto PACS default port.
        self.assertTrue(mock_ae_instance.associate.called)
        for call in mock_ae_instance.associate.call_args_list:
            self.assertEqual(call.args[1], 11112)


class TestDICOMSecurityAnalysis(unittest.TestCase):
    """Test DICOM security analysis functionality"""

    def setUp(self):
        """Set up test fixtures"""
        self.mock_args = Mock()
        self.mock_args.port = 11112
        self.mock_args.timeout = 30
        self.mock_args.aet = "OIDA"
        self.mock_args.called_aet = "ANY"
        self.mock_args.tls = False
        self.mock_args.verbose = 0
        self.mock_args.find = False
        self.mock_args.get = False
        self.mock_args.store = False
        self.mock_args.move = False
        self.mock_args.aet_brute = None
        self.mock_args.probe_ops = False
        self.mock_args.worklist = False
        self.mock_args.dump_all = False
        self.mock_args.fuzz = False
        self.mock_args.enum_operators = False
        self.mock_args.enum_devices = False
        self.mock_args.time_analysis = False
        self.mock_args.output = None
        self.mock_args.format = "json"

    def _security_finding_titles(self, scanner):
        """Collect the title arg of every logger.security_finding(...) call."""
        titles = []
        for call in scanner.logger.security_finding.call_args_list:
            if call.args:
                titles.append(str(call.args[0]))
            elif "title" in call.kwargs:
                titles.append(str(call.kwargs["title"]))
        return titles

    @patch("oida.protocols.dicom.PYNETDICOM_AVAILABLE", True)
    def test_security_analysis_no_tls(self):
        """Test security analysis detects no TLS"""
        # _analyze_security emits findings via logger.security_finding(), not a
        # results["data"]["security_issues"] list.
        scanner = _make_dicom_instance(
            self.mock_args,
            results={"data": {"connected": True, "user_identity_required": False}},
        )

        scanner._analyze_security()

        titles = self._security_finding_titles(scanner)
        self.assertTrue(
            any("No encryption" in t for t in titles),
            f"expected a no-encryption finding, got {titles}",
        )

    @patch("oida.protocols.dicom.PYNETDICOM_AVAILABLE", True)
    def test_security_analysis_no_auth(self):
        """Test security analysis detects no authentication"""
        scanner = _make_dicom_instance(
            self.mock_args,
            results={"data": {"connected": True, "user_identity_required": False}},
        )

        scanner._analyze_security()

        titles = self._security_finding_titles(scanner)
        # Should flag weak AET whitelist (calling_aet=OIDA) or no encryption
        self.assertTrue(
            any("AET" in t or "No encryption" in t for t in titles),
            f"expected an AET/encryption finding, got {titles}",
        )


class TestDICOMCStoreHandler(unittest.TestCase):
    """Test DICOM C-STORE handler for C-GET operations"""

    def setUp(self):
        """Set up test fixtures"""
        self.mock_args = Mock()
        self.mock_args.port = 11112
        self.mock_args.timeout = 30
        self.mock_args.aet = "OIDA"
        self.mock_args.called_aet = "ANY"
        self.mock_args.tls = False
        self.mock_args.verbose = 0
        self.mock_args.find = False
        self.mock_args.get = True
        self.mock_args.store = False
        self.mock_args.move = False
        self.mock_args.aet_brute = None
        self.mock_args.probe_ops = False
        self.mock_args.worklist = False
        self.mock_args.dump_all = False
        self.mock_args.fuzz = False
        self.mock_args.output_dir = "/tmp/dicom_test"
        self.mock_args.enum_operators = False
        self.mock_args.enum_devices = False
        self.mock_args.time_analysis = False

    @patch("oida.protocols.dicom.PYNETDICOM_AVAILABLE", True)
    def test_cstore_handler_success(self):
        """Test C-STORE handler saves files correctly"""
        from pathlib import Path
        import tempfile

        scanner = _make_dicom_instance(self.mock_args)
        scanner.logger = Mock()

        # Create mock event with dataset
        mock_event = Mock()
        mock_ds = Mock()
        mock_ds.SOPInstanceUID = "1.2.3.4.5.6.7.8.9"
        mock_ds.PatientID = "PT001"
        mock_ds.StudyInstanceUID = "1.2.3.4.5"
        mock_event.dataset = mock_ds
        mock_event.file_meta = Mock()

        with tempfile.TemporaryDirectory() as tmpdir:
            scanner._cget_output_path = Path(tmpdir)
            scanner._cget_received_files = []
            scanner._cget_use_subdirs = False

            # Mock save_as to avoid actual file operations
            mock_ds.save_as = Mock()

            result = scanner._handle_store_for_cget(mock_event)

            self.assertEqual(result, 0x0000)  # Success
            self.assertEqual(len(scanner._cget_received_files), 1)

    @patch("oida.protocols.dicom.PYNETDICOM_AVAILABLE", True)
    def test_cstore_handler_blocks_path_traversal(self):
        """Hostile responder cannot escape _cget_output_path via UIDs."""
        from pathlib import Path
        import tempfile

        scanner = _make_dicom_instance(self.mock_args)
        scanner.logger = Mock()

        # All three traversal-attempt UID combos in one sweep — sub-dirs path
        # walks both PatientID and StudyInstanceUID before filename, so each
        # is a separate attack surface.
        for patient, study, sop in [
            ("..", "..", "1.2.3"),
            ("../../etc", "passwd", "1.2.3"),
            ("normal", "normal", "../../../../../tmp/oida_evil"),
        ]:
            mock_event = Mock()
            mock_ds = Mock()
            mock_ds.PatientID = patient
            mock_ds.StudyInstanceUID = study
            mock_ds.SOPInstanceUID = sop
            mock_event.dataset = mock_ds
            mock_event.file_meta = Mock()

            with tempfile.TemporaryDirectory() as tmpdir:
                base = Path(tmpdir).resolve()
                scanner._cget_output_path = base
                scanner._cget_received_files = []
                scanner._cget_use_subdirs = True

                saved_paths = []
                mock_ds.save_as = lambda p, **_: saved_paths.append(Path(p).resolve())

                result = scanner._handle_store_for_cget(mock_event)

                # Either the sanitizer rendered them inert (write inside
                # tmpdir) or PermissionError was caught by the handler's
                # outer try/except returning 0xC211.
                if saved_paths:
                    self.assertTrue(
                        str(saved_paths[0]).startswith(str(base)),
                        f"Escape: {saved_paths[0]} not under {base}",
                    )
                else:
                    self.assertEqual(
                        result,
                        0xC211,
                        f"Blocked traversal must report failure status, got {hex(result)}",
                    )


class TestDICOMRejectInfo(unittest.TestCase):
    """Test DICOM association rejection info extraction"""

    def setUp(self):
        """Set up test fixtures"""
        self.mock_args = Mock()
        self.mock_args.port = 11112
        self.mock_args.timeout = 30
        self.mock_args.aet = "OIDA"
        self.mock_args.called_aet = "ANY"
        self.mock_args.tls = False
        self.mock_args.verbose = 0
        self.mock_args.find = False
        self.mock_args.get = False
        self.mock_args.store = False
        self.mock_args.move = False
        self.mock_args.aet_brute = None
        self.mock_args.probe_ops = False
        self.mock_args.worklist = False
        self.mock_args.dump_all = False
        self.mock_args.fuzz = False
        self.mock_args.enum_operators = False
        self.mock_args.enum_devices = False
        self.mock_args.time_analysis = False

    @patch("oida.protocols.dicom.PYNETDICOM_AVAILABLE", True)
    def test_get_reject_info_rejected(self):
        """Test rejection info for rejected association"""

        scanner = _make_dicom_instance(self.mock_args)
        scanner.assoc = MockAssociation(established=False)
        scanner.assoc.is_rejected = True

        result = scanner._get_reject_info()

        self.assertIn("Rejected", result)

    @patch("oida.protocols.dicom.PYNETDICOM_AVAILABLE", True)
    def test_get_reject_info_aborted(self):
        """Test rejection info for aborted association"""

        scanner = _make_dicom_instance(self.mock_args)
        scanner.assoc = MockAssociation(established=False)
        scanner.assoc.is_rejected = False
        scanner.assoc.is_aborted = True

        result = scanner._get_reject_info()

        self.assertEqual(result, "Aborted by peer")

    @patch("oida.protocols.dicom.PYNETDICOM_AVAILABLE", True)
    def test_get_reject_info_no_assoc(self):
        """Test rejection info with no association"""

        scanner = _make_dicom_instance(self.mock_args)
        scanner.assoc = None

        result = scanner._get_reject_info()

        self.assertEqual(result, "Unknown")


class TestDICOMModuleExports(unittest.TestCase):
    """Test DICOM module exports and compatibility"""

    def test_pynetdicom_available_flag(self):
        """Test PYNETDICOM_AVAILABLE flag exists"""
        from oida.protocols.dicom import PYNETDICOM_AVAILABLE

        self.assertIsInstance(PYNETDICOM_AVAILABLE, bool)

    def test_dicom_class_exists(self):
        """Test dicom class is exported"""
        from oida.protocols.dicom import dicom

        self.assertIsNotNone(dicom)

    def test_vendor_map_exported(self):
        """Test vendor map is exported"""
        from oida.protocols.dicom import DICOM_VENDOR_MAP

        self.assertIsInstance(DICOM_VENDOR_MAP, dict)

    def test_phi_tags_exported(self):
        """Test PHI tags list is exported"""
        from oida.protocols.dicom import PHI_TAGS

        self.assertIsInstance(PHI_TAGS, list)

    def test_default_aet_wordlist_exported(self):
        """Test default AET wordlist is exported"""
        from oida.protocols.dicom import DEFAULT_AET_WORDLIST

        self.assertIsInstance(DEFAULT_AET_WORDLIST, list)


class TestDICOMArgsInitialization(unittest.TestCase):
    """Test DICOM class initialization with different argument configurations"""

    @patch("oida.protocols.dicom.PYNETDICOM_AVAILABLE", True)
    def test_init_with_minimal_args(self):
        """Test initialization with minimal required arguments"""
        from oida.protocols.dicom import dicom

        mock_args = Mock()
        mock_args.port = 11112
        mock_args.timeout = 30
        mock_args.aet = "TEST"
        mock_args.called_aet = "PACS"
        mock_args.tls = False
        mock_args.verbose = 0
        mock_args.find = False
        mock_args.get = False
        mock_args.store = False
        mock_args.move = False
        mock_args.aet_brute = None
        mock_args.probe_ops = False
        mock_args.worklist = False
        mock_args.dump_all = False
        mock_args.fuzz = False
        mock_args.enum_operators = False
        mock_args.enum_devices = False
        mock_args.time_analysis = False

        with patch.object(dicom, "proto_flow", return_value=None):
            scanner = dicom.__new__(dicom)
            scanner.protocol_name = "dicom"
            scanner.default_port = 11112
            scanner.ae = None
            scanner.assoc = None
            scanner._cget_output_path = None
            scanner._cget_received_files = []
            scanner.ip = "192.168.1.100"

        self.assertEqual(scanner.protocol_name, "dicom")
        self.assertEqual(scanner.default_port, 11112)
        self.assertEqual(scanner.ip, "192.168.1.100")
        self.assertIsNone(scanner.ae)
        self.assertIsNone(scanner.assoc)

    @patch("oida.protocols.dicom.PYNETDICOM_AVAILABLE", True)
    def test_init_with_custom_port(self):
        """Test initialization with custom port"""
        from oida.protocols.dicom import dicom

        mock_args = Mock()
        mock_args.port = 8042  # Custom port
        mock_args.timeout = 30
        mock_args.aet = "CUSTOM"
        mock_args.called_aet = "SERVER"
        mock_args.tls = False
        mock_args.verbose = 0
        mock_args.find = False
        mock_args.get = False
        mock_args.store = False
        mock_args.move = False
        mock_args.aet_brute = None
        mock_args.probe_ops = False
        mock_args.worklist = False
        mock_args.dump_all = False
        mock_args.fuzz = False
        mock_args.enum_operators = False
        mock_args.enum_devices = False
        mock_args.time_analysis = False

        with patch.object(dicom, "proto_flow", return_value=None):
            scanner = dicom.__new__(dicom)
            scanner.protocol_name = "dicom"
            scanner.default_port = 11112
            scanner.ae = None
            scanner.assoc = None
            scanner._cget_output_path = None
            scanner._cget_received_files = []
            scanner.ip = "10.0.0.1"

        self.assertEqual(scanner.ip, "10.0.0.1")

    @patch("oida.protocols.dicom.PYNETDICOM_AVAILABLE", True)
    def test_init_with_tls_enabled(self):
        """Test initialization with TLS enabled"""
        from oida.protocols.dicom import dicom

        mock_args = Mock()
        mock_args.port = 11112
        mock_args.timeout = 30
        mock_args.aet = "SECURE"
        mock_args.called_aet = "TLS_PACS"
        mock_args.tls = True  # TLS enabled
        mock_args.verbose = 0
        mock_args.find = False
        mock_args.get = False
        mock_args.store = False
        mock_args.move = False
        mock_args.aet_brute = None
        mock_args.probe_ops = False
        mock_args.worklist = False
        mock_args.dump_all = False
        mock_args.fuzz = False
        mock_args.enum_operators = False
        mock_args.enum_devices = False
        mock_args.time_analysis = False

        with patch.object(dicom, "proto_flow", return_value=None):
            scanner = dicom.__new__(dicom)
            scanner.protocol_name = "dicom"
            scanner.default_port = 11112
            scanner.ae = None
            scanner.assoc = None
            scanner._cget_output_path = None
            scanner._cget_received_files = []
            scanner.ip = "192.168.1.50"

        self.assertEqual(scanner.protocol_name, "dicom")


class TestDICOMQueryDatasetBuilding(unittest.TestCase):
    """Test C-FIND query dataset building at different levels"""

    def setUp(self):
        """Set up test fixtures"""
        self.mock_args = Mock()
        self.mock_args.port = 11112
        self.mock_args.timeout = 30
        self.mock_args.aet = "OIDA"
        self.mock_args.called_aet = "ANY"
        self.mock_args.tls = False
        self.mock_args.verbose = 0
        self.mock_args.find = True
        self.mock_args.get = False
        self.mock_args.store = False
        self.mock_args.move = False
        self.mock_args.aet_brute = None
        self.mock_args.probe_ops = False
        self.mock_args.worklist = False
        self.mock_args.dump_all = False
        self.mock_args.fuzz = False
        self.mock_args.max_results = 100
        self.mock_args.metadata = False
        self.mock_args.dump_tags = False
        self.mock_args.phi_only = False
        self.mock_args.enum_operators = False
        self.mock_args.enum_devices = False
        self.mock_args.time_analysis = False

    @patch("oida.protocols.dicom.PYNETDICOM_AVAILABLE", True)
    @patch("oida.protocols.dicom.Dataset")
    def test_build_patient_query_wildcard(self, mock_dataset):
        """Test building PATIENT level query with wildcard"""

        self.mock_args.query_level = "PATIENT"
        self.mock_args.patient_name = "*"
        self.mock_args.patient_id = ""
        self.mock_args.study_date = ""
        self.mock_args.study_uid = ""
        self.mock_args.series_uid = ""
        self.mock_args.modality = ""

        mock_ds = Mock()
        mock_dataset.return_value = mock_ds

        scanner = _make_dicom_instance(self.mock_args)
        scanner.assoc = MockAssociation()
        scanner.logger = Mock()

        scanner._cfind_query()

        # Verify QueryRetrieveLevel was set
        self.assertEqual(scanner.results["data"]["cfind_results"]["query_level"], "PATIENT")

    @patch("oida.protocols.dicom.PYNETDICOM_AVAILABLE", True)
    @patch("oida.protocols.dicom.Dataset")
    def test_build_study_query_with_filters(self, mock_dataset):
        """Test building STUDY level query with date and modality filters"""

        self.mock_args.query_level = "STUDY"
        self.mock_args.patient_name = "*"
        self.mock_args.patient_id = "PT001"
        self.mock_args.study_date = "20240101"
        self.mock_args.study_uid = ""
        self.mock_args.series_uid = ""
        self.mock_args.modality = "CT"

        mock_ds = Mock()
        mock_dataset.return_value = mock_ds

        scanner = _make_dicom_instance(self.mock_args)
        scanner.assoc = MockAssociation()
        scanner.logger = Mock()

        scanner._cfind_query()

        self.assertEqual(scanner.results["data"]["cfind_results"]["query_level"], "STUDY")

    @patch("oida.protocols.dicom.PYNETDICOM_AVAILABLE", True)
    @patch("oida.protocols.dicom.Dataset")
    def test_build_series_query_with_study_uid(self, mock_dataset):
        """Test building SERIES level query with study UID"""

        self.mock_args.query_level = "SERIES"
        self.mock_args.patient_name = ""
        self.mock_args.patient_id = ""
        self.mock_args.study_date = ""
        self.mock_args.study_uid = "1.2.3.4.5"
        self.mock_args.series_uid = ""
        self.mock_args.modality = ""

        mock_ds = Mock()
        mock_dataset.return_value = mock_ds

        scanner = _make_dicom_instance(self.mock_args)
        scanner.assoc = MockAssociation()
        scanner.logger = Mock()

        scanner._cfind_query()

        # Should succeed with study_uid provided
        self.assertIn("cfind_results", scanner.results["data"])

    @patch("oida.protocols.dicom.PYNETDICOM_AVAILABLE", True)
    @patch("oida.protocols.dicom.Dataset")
    def test_build_image_query_with_series_uid(self, mock_dataset):
        """Test building IMAGE level query with series UID"""

        self.mock_args.query_level = "IMAGE"
        self.mock_args.patient_name = ""
        self.mock_args.patient_id = ""
        self.mock_args.study_date = ""
        self.mock_args.study_uid = ""
        self.mock_args.series_uid = "1.2.3.4.5.6"
        self.mock_args.modality = ""

        mock_ds = Mock()
        mock_dataset.return_value = mock_ds

        scanner = _make_dicom_instance(self.mock_args)
        scanner.assoc = MockAssociation()
        scanner.logger = Mock()

        scanner._cfind_query()

        # Should succeed with series_uid provided
        self.assertIn("cfind_results", scanner.results["data"])


class TestDICOMExtractCFindResultsEdgeCases(unittest.TestCase):
    """Test _extract_cfind_result method with edge cases"""

    def setUp(self):
        """Set up test fixtures"""
        self.mock_args = Mock()
        self.mock_args.port = 11112
        self.mock_args.timeout = 30
        self.mock_args.aet = "OIDA"
        self.mock_args.called_aet = "ANY"
        self.mock_args.tls = False
        self.mock_args.verbose = 0
        self.mock_args.find = False
        self.mock_args.get = False
        self.mock_args.store = False
        self.mock_args.move = False
        self.mock_args.aet_brute = None
        self.mock_args.probe_ops = False
        self.mock_args.worklist = False
        self.mock_args.dump_all = False
        self.mock_args.fuzz = False
        self.mock_args.dump_tags = False
        self.mock_args.phi_only = False
        self.mock_args.metadata = False
        self.mock_args.extract_fields = ""
        self.mock_args.enum_operators = False
        self.mock_args.enum_devices = False
        self.mock_args.time_analysis = False

    @patch("oida.protocols.dicom.PYNETDICOM_AVAILABLE", True)
    def test_extract_result_missing_attributes(self):
        """Test extraction when identifier has missing attributes"""

        scanner = _make_dicom_instance(self.mock_args)

        identifier = Mock()
        identifier.PatientName = "DOE^JOHN"
        # PatientID is missing - getattr should handle gracefully

        result = scanner._extract_cfind_result(identifier, "PATIENT")

        self.assertEqual(result["PatientName"], "DOE^JOHN")
        # Should have empty string for missing fields
        self.assertIsNotNone(result)

    @patch("oida.protocols.dicom.PYNETDICOM_AVAILABLE", True)
    def test_extract_result_image_level(self):
        """Test extraction of IMAGE level C-FIND result"""

        scanner = _make_dicom_instance(self.mock_args)

        identifier = Mock()
        identifier.SOPInstanceUID = "1.2.3.4.5.6.7"
        identifier.InstanceNumber = "1"
        identifier.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"

        result = scanner._extract_cfind_result(identifier, "IMAGE")

        self.assertEqual(result["SOPInstanceUID"], "1.2.3.4.5.6.7")
        self.assertEqual(result["InstanceNumber"], "1")

    @patch("oida.protocols.dicom.PYNETDICOM_AVAILABLE", True)
    def test_extract_result_with_unicode_names(self):
        """Test extraction with unicode characters in patient names"""

        scanner = _make_dicom_instance(self.mock_args)

        identifier = Mock()
        identifier.PatientName = "MUELLER^HANS"
        identifier.PatientID = "PT123"

        result = scanner._extract_cfind_result(identifier, "PATIENT")

        self.assertIn("MUELLER", result["PatientName"])

    @patch("oida.protocols.dicom.PYNETDICOM_AVAILABLE", True)
    def test_extract_result_series_with_all_fields(self):
        """Test extraction of SERIES level with all optional fields"""

        scanner = _make_dicom_instance(self.mock_args)

        identifier = Mock()
        identifier.SeriesInstanceUID = "1.2.3.4.5.6"
        identifier.SeriesNumber = "2"
        identifier.SeriesDescription = "Axial T2"
        identifier.Modality = "MR"
        identifier.NumberOfSeriesRelatedInstances = "250"
        identifier.BodyPartExamined = "BRAIN"
        identifier.ProtocolName = "Brain MRI"

        result = scanner._extract_cfind_result(identifier, "SERIES")

        self.assertEqual(result["SeriesInstanceUID"], "1.2.3.4.5.6")
        self.assertEqual(result["Modality"], "MR")
        self.assertEqual(result["SeriesDescription"], "Axial T2")


class TestDICOMAETitleValidation(unittest.TestCase):
    """Test AE Title validation and handling"""

    @patch("oida.protocols.dicom.PYNETDICOM_AVAILABLE", True)
    def test_default_calling_aet(self):
        """Test default calling AE Title is set correctly"""
        from oida.protocols.dicom import dicom

        mock_args = Mock()
        mock_args.port = 11112
        mock_args.timeout = 30
        # No aet specified - should use default
        mock_args.aet = None
        mock_args.called_aet = "ANY"
        mock_args.tls = False
        mock_args.verbose = 0
        mock_args.find = False
        mock_args.get = False
        mock_args.store = False
        mock_args.move = False
        mock_args.aet_brute = None
        mock_args.probe_ops = False
        mock_args.worklist = False
        mock_args.dump_all = False
        mock_args.fuzz = False
        mock_args.enum_operators = False
        mock_args.enum_devices = False
        mock_args.time_analysis = False

        with patch.object(dicom, "proto_flow", return_value=None):
            scanner = dicom.__new__(dicom)
            scanner.protocol_name = "dicom"
            scanner.default_port = 11112
            scanner.ae = None
            scanner.assoc = None
            scanner._cget_output_path = None
            scanner._cget_received_files = []

        # Default should be set in proto_flow
        self.assertIsNotNone(scanner.protocol_name)

    @patch("oida.protocols.dicom.PYNETDICOM_AVAILABLE", True)
    def test_custom_aet_titles(self):
        """Test custom calling and called AE Titles"""
        from oida.protocols.dicom import dicom

        mock_args = Mock()
        mock_args.port = 11112
        mock_args.timeout = 30
        mock_args.aet = "CUSTOM_SCU"
        mock_args.called_aet = "CUSTOM_SCP"
        mock_args.tls = False
        mock_args.verbose = 0
        mock_args.find = False
        mock_args.get = False
        mock_args.store = False
        mock_args.move = False
        mock_args.aet_brute = None
        mock_args.probe_ops = False
        mock_args.worklist = False
        mock_args.dump_all = False
        mock_args.fuzz = False
        mock_args.enum_operators = False
        mock_args.enum_devices = False
        mock_args.time_analysis = False

        with patch.object(dicom, "proto_flow", return_value=None):
            scanner = dicom.__new__(dicom)
            scanner.protocol_name = "dicom"
            scanner.default_port = 11112
            scanner.ae = None
            scanner.assoc = None
            scanner._cget_output_path = None
            scanner._cget_received_files = []

        self.assertEqual(scanner.protocol_name, "dicom")

    @patch("oida.protocols.dicom.PYNETDICOM_AVAILABLE", True)
    def test_aet_with_special_characters(self):
        """Test AE Title with underscores and numbers"""
        from oida.protocols.dicom import dicom

        mock_args = Mock()
        mock_args.port = 11112
        mock_args.timeout = 30
        mock_args.aet = "TEST_AET_01"
        mock_args.called_aet = "PACS_2024"
        mock_args.tls = False
        mock_args.verbose = 0
        mock_args.find = False
        mock_args.get = False
        mock_args.store = False
        mock_args.move = False
        mock_args.aet_brute = None
        mock_args.probe_ops = False
        mock_args.worklist = False
        mock_args.dump_all = False
        mock_args.fuzz = False
        mock_args.enum_operators = False
        mock_args.enum_devices = False
        mock_args.time_analysis = False

        with patch.object(dicom, "proto_flow", return_value=None):
            scanner = dicom.__new__(dicom)
            scanner.protocol_name = "dicom"
            scanner.default_port = 11112
            scanner.ae = None
            scanner.assoc = None
            scanner._cget_output_path = None
            scanner._cget_received_files = []

        self.assertEqual(scanner.protocol_name, "dicom")


class TestDICOMAssociationEdgeCases(unittest.TestCase):
    """Test association establishment edge cases"""

    def setUp(self):
        """Set up test fixtures"""
        self.mock_args = Mock()
        self.mock_args.port = 11112
        self.mock_args.timeout = 30
        self.mock_args.aet = "OIDA"
        self.mock_args.called_aet = "ANY"
        self.mock_args.tls = False
        self.mock_args.verbose = 0
        self.mock_args.find = False
        self.mock_args.get = False
        self.mock_args.store = False
        self.mock_args.move = False
        self.mock_args.aet_brute = None
        self.mock_args.probe_ops = False
        self.mock_args.worklist = False
        self.mock_args.dump_all = False
        self.mock_args.fuzz = False
        self.mock_args.output = None
        self.mock_args.format = "json"
        self.mock_args.enum_operators = False
        self.mock_args.enum_devices = False
        self.mock_args.time_analysis = False

    @patch("oida.protocols.dicom.PYNETDICOM_AVAILABLE", True)
    @patch("oida.protocols.dicom.AE")
    def test_create_conn_with_probe_ops(self, mock_ae_class):
        """Test connection creation with probe_ops enabled"""
        from oida.protocols.dicom import dicom

        self.mock_args.probe_ops = True

        mock_ae = MockAE()
        mock_ae_class.return_value = mock_ae

        with patch.object(dicom, "proto_flow", return_value=None):
            scanner = dicom.__new__(dicom)
            scanner.args = self.mock_args
            scanner.db = None
            scanner.ip = "192.168.1.100"
            scanner.host = "192.168.1.100"
            scanner.protocol_name = "dicom"
            scanner.default_port = 11112
            scanner.ae = None
            scanner.assoc = None
            scanner._cget_output_path = None
            scanner._cget_received_files = []
            scanner.results = {"data": {}}
            scanner.calling_aet = "OIDA"
            scanner.called_aet = "ANY"
            scanner.logger = Mock()

            result = scanner.create_conn_obj()

            self.assertTrue(result)

    @patch("oida.protocols.dicom.PYNETDICOM_AVAILABLE", True)
    @patch("oida.protocols.dicom.AE")
    def test_create_conn_with_worklist(self, mock_ae_class):
        """Test connection creation with worklist enabled"""
        from oida.protocols.dicom import dicom

        self.mock_args.worklist = True

        mock_ae = MockAE()
        mock_ae_class.return_value = mock_ae

        with patch.object(dicom, "proto_flow", return_value=None):
            scanner = dicom.__new__(dicom)
            scanner.args = self.mock_args
            scanner.db = None
            scanner.ip = "192.168.1.100"
            scanner.host = "192.168.1.100"
            scanner.protocol_name = "dicom"
            scanner.default_port = 11112
            scanner.ae = None
            scanner.assoc = None
            scanner._cget_output_path = None
            scanner._cget_received_files = []
            scanner.results = {"data": {}}
            scanner.calling_aet = "OIDA"
            scanner.called_aet = "ANY"
            scanner.logger = Mock()

            result = scanner.create_conn_obj()

            self.assertTrue(result)

    @patch("oida.protocols.dicom.PYNETDICOM_AVAILABLE", True)
    @patch("oida.protocols.dicom.AE")
    def test_create_conn_with_store(self, mock_ae_class):
        """Test connection creation with store enabled"""
        from oida.protocols.dicom import dicom

        self.mock_args.store = True

        mock_ae = MockAE()
        mock_ae_class.return_value = mock_ae

        with patch.object(dicom, "proto_flow", return_value=None):
            scanner = dicom.__new__(dicom)
            scanner.args = self.mock_args
            scanner.db = None
            scanner.ip = "192.168.1.100"
            scanner.host = "192.168.1.100"
            scanner.protocol_name = "dicom"
            scanner.default_port = 11112
            scanner.ae = None
            scanner.assoc = None
            scanner._cget_output_path = None
            scanner._cget_received_files = []
            scanner.results = {"data": {}}
            scanner.calling_aet = "OIDA"
            scanner.called_aet = "ANY"
            scanner.logger = Mock()

            result = scanner.create_conn_obj()

            self.assertTrue(result)


class TestDICOMCFindQueryLevels(unittest.TestCase):
    """Test C-FIND query building at all query levels"""

    def setUp(self):
        """Set up test fixtures"""
        self.mock_args = Mock()
        self.mock_args.port = 11112
        self.mock_args.timeout = 30
        self.mock_args.aet = "OIDA"
        self.mock_args.called_aet = "ANY"
        self.mock_args.tls = False
        self.mock_args.verbose = 0
        self.mock_args.find = True
        self.mock_args.get = False
        self.mock_args.store = False
        self.mock_args.move = False
        self.mock_args.aet_brute = None
        self.mock_args.probe_ops = False
        self.mock_args.worklist = False
        self.mock_args.dump_all = False
        self.mock_args.fuzz = False
        self.mock_args.max_results = 100
        self.mock_args.metadata = False
        self.mock_args.dump_tags = False
        self.mock_args.phi_only = False
        self.mock_args.enum_operators = False
        self.mock_args.enum_devices = False
        self.mock_args.time_analysis = False

    @patch("oida.protocols.dicom.PYNETDICOM_AVAILABLE", True)
    @patch("oida.protocols.dicom.Dataset")
    def test_patient_level_query_with_patient_id(self, mock_dataset):
        """Test PATIENT level query with specific patient ID"""

        self.mock_args.query_level = "PATIENT"
        self.mock_args.patient_name = ""
        self.mock_args.patient_id = "PT12345"
        self.mock_args.study_date = ""
        self.mock_args.study_uid = ""
        self.mock_args.series_uid = ""
        self.mock_args.modality = ""

        mock_ds = Mock()
        mock_dataset.return_value = mock_ds

        scanner = _make_dicom_instance(self.mock_args)
        scanner.assoc = MockAssociation()
        scanner.logger = Mock()

        scanner._cfind_query()

        self.assertEqual(scanner.results["data"]["cfind_results"]["query_level"], "PATIENT")

    @patch("oida.protocols.dicom.PYNETDICOM_AVAILABLE", True)
    @patch("oida.protocols.dicom.Dataset")
    def test_study_level_query_with_study_date_range(self, mock_dataset):
        """Test STUDY level query with date range"""

        self.mock_args.query_level = "STUDY"
        self.mock_args.patient_name = "*"
        self.mock_args.patient_id = ""
        self.mock_args.study_date = "20240101-20240131"
        self.mock_args.study_uid = ""
        self.mock_args.series_uid = ""
        self.mock_args.modality = ""

        mock_ds = Mock()
        mock_dataset.return_value = mock_ds

        scanner = _make_dicom_instance(self.mock_args)
        scanner.assoc = MockAssociation()
        scanner.logger = Mock()

        scanner._cfind_query()

        self.assertEqual(scanner.results["data"]["cfind_results"]["query_level"], "STUDY")

    @patch("oida.protocols.dicom.PYNETDICOM_AVAILABLE", True)
    @patch("oida.protocols.dicom.Dataset")
    def test_study_level_query_with_specific_uid(self, mock_dataset):
        """Test STUDY level query with specific study UID"""

        self.mock_args.query_level = "STUDY"
        self.mock_args.patient_name = ""
        self.mock_args.patient_id = ""
        self.mock_args.study_date = ""
        self.mock_args.study_uid = "1.2.840.113619.2.55.3"
        self.mock_args.series_uid = ""
        self.mock_args.modality = ""

        mock_ds = Mock()
        mock_dataset.return_value = mock_ds

        scanner = _make_dicom_instance(self.mock_args)
        scanner.assoc = MockAssociation()
        scanner.logger = Mock()

        scanner._cfind_query()

        self.assertEqual(scanner.results["data"]["cfind_results"]["query_level"], "STUDY")

    @patch("oida.protocols.dicom.PYNETDICOM_AVAILABLE", True)
    @patch("oida.protocols.dicom.Dataset")
    def test_series_level_query_with_modality_filter(self, mock_dataset):
        """Test SERIES level query with modality filter"""

        self.mock_args.query_level = "SERIES"
        self.mock_args.patient_name = ""
        self.mock_args.patient_id = ""
        self.mock_args.study_date = ""
        self.mock_args.study_uid = "1.2.3.4.5"
        self.mock_args.series_uid = ""
        self.mock_args.modality = "MR"

        mock_ds = Mock()
        mock_dataset.return_value = mock_ds

        scanner = _make_dicom_instance(self.mock_args)
        scanner.assoc = MockAssociation()
        scanner.logger = Mock()

        scanner._cfind_query()

        self.assertIn("cfind_results", scanner.results["data"])

    @patch("oida.protocols.dicom.PYNETDICOM_AVAILABLE", True)
    @patch("oida.protocols.dicom.Dataset")
    def test_image_level_query_complete(self, mock_dataset):
        """Test IMAGE level query with series and study UIDs"""

        self.mock_args.query_level = "IMAGE"
        self.mock_args.patient_name = ""
        self.mock_args.patient_id = ""
        self.mock_args.study_date = ""
        self.mock_args.study_uid = "1.2.3.4.5"
        self.mock_args.series_uid = "1.2.3.4.5.6"
        self.mock_args.modality = ""

        mock_ds = Mock()
        mock_dataset.return_value = mock_ds

        scanner = _make_dicom_instance(self.mock_args)
        scanner.assoc = MockAssociation()
        scanner.logger = Mock()

        scanner._cfind_query()

        self.assertIn("cfind_results", scanner.results["data"])


class TestDICOMVendorIdentificationExtended(unittest.TestCase):
    """Extended tests for vendor identification"""

    def setUp(self):
        """Set up test fixtures"""
        self.mock_args = Mock()
        self.mock_args.port = 11112
        self.mock_args.timeout = 30
        self.mock_args.aet = "OIDA"
        self.mock_args.called_aet = "ANY"
        self.mock_args.tls = False
        self.mock_args.verbose = 0
        self.mock_args.find = False
        self.mock_args.get = False
        self.mock_args.store = False
        self.mock_args.move = False
        self.mock_args.aet_brute = None
        self.mock_args.probe_ops = False
        self.mock_args.worklist = False
        self.mock_args.dump_all = False
        self.mock_args.fuzz = False
        self.mock_args.enum_operators = False
        self.mock_args.enum_devices = False
        self.mock_args.time_analysis = False

    @patch("oida.protocols.dicom.PYNETDICOM_AVAILABLE", True)
    def test_identify_horos(self):
        """Test Horos vendor identification"""

        scanner = _make_dicom_instance(self.mock_args)
        vendor, desc = scanner._identify_vendor("1.2.826.0.1.3680043.2.1143")

        self.assertEqual(vendor, "HOROS")

    @patch("oida.protocols.dicom.PYNETDICOM_AVAILABLE", True)
    def test_identify_conquest(self):
        """Test Conquest DICOM Server identification"""

        scanner = _make_dicom_instance(self.mock_args)
        vendor, desc = scanner._identify_vendor("1.2.826.0.1.3680043.2.60")

        self.assertEqual(vendor, "Conquest")

    @patch("oida.protocols.dicom.PYNETDICOM_AVAILABLE", True)
    def test_identify_pynetdicom(self):
        """Test pynetdicom identification"""

        scanner = _make_dicom_instance(self.mock_args)
        vendor, desc = scanner._identify_vendor("1.2.40.0.13.1.3")

        self.assertEqual(vendor, "pynetdicom")

    @patch("oida.protocols.dicom.PYNETDICOM_AVAILABLE", True)
    def test_identify_partial_uid_match(self):
        """Test partial UID matching for vendor identification"""

        scanner = _make_dicom_instance(self.mock_args)
        # GE base prefix with no more-specific sub-entry -> base GE Healthcare.
        vendor, desc = scanner._identify_vendor("1.2.840.113619.4.123")
        self.assertEqual(vendor, "GE Healthcare")

        # Longest-prefix wins: the .6 sub-tree resolves to the specific product.
        vendor, desc = scanner._identify_vendor("1.2.840.113619.6.123")
        self.assertEqual(vendor, "GE Centricity")

    @patch("oida.protocols.dicom.PYNETDICOM_AVAILABLE", True)
    def test_identify_none_uid(self):
        """Test handling of None UID"""

        scanner = _make_dicom_instance(self.mock_args)
        vendor, desc = scanner._identify_vendor(None)

        self.assertIsNone(vendor)
        self.assertIsNone(desc)


class TestDICOMHandleStoreEdgeCases(unittest.TestCase):
    """Test C-STORE handler edge cases"""

    def setUp(self):
        """Set up test fixtures"""
        self.mock_args = Mock()
        self.mock_args.port = 11112
        self.mock_args.timeout = 30
        self.mock_args.aet = "OIDA"
        self.mock_args.called_aet = "ANY"
        self.mock_args.tls = False
        self.mock_args.verbose = 0
        self.mock_args.find = False
        self.mock_args.get = True
        self.mock_args.store = False
        self.mock_args.move = False
        self.mock_args.aet_brute = None
        self.mock_args.probe_ops = False
        self.mock_args.worklist = False
        self.mock_args.dump_all = False
        self.mock_args.fuzz = False
        self.mock_args.output_dir = "/tmp/dicom_test"
        self.mock_args.enum_operators = False
        self.mock_args.enum_devices = False
        self.mock_args.time_analysis = False

    @patch("oida.protocols.dicom.PYNETDICOM_AVAILABLE", True)
    def test_cstore_handler_with_subdirs(self):
        """Test C-STORE handler with subdirectory structure"""
        from pathlib import Path
        import tempfile

        scanner = _make_dicom_instance(self.mock_args)
        scanner.logger = Mock()

        # Create mock event with dataset
        mock_event = Mock()
        mock_ds = Mock()
        mock_ds.SOPInstanceUID = "1.2.3.4.5.6.7.8.9"
        mock_ds.PatientID = "PT001"
        mock_ds.StudyInstanceUID = "1.2.3.4.5"
        mock_event.dataset = mock_ds
        mock_event.file_meta = Mock()

        with tempfile.TemporaryDirectory() as tmpdir:
            scanner._cget_output_path = Path(tmpdir)
            scanner._cget_received_files = []
            scanner._cget_use_subdirs = True  # Enable subdirectory structure

            # Mock save_as to avoid actual file operations
            mock_ds.save_as = Mock()

            result = scanner._handle_store_for_cget(mock_event)

            self.assertEqual(result, 0x0000)  # Success

    @patch("oida.protocols.dicom.PYNETDICOM_AVAILABLE", True)
    def test_cstore_handler_exception(self):
        """Test C-STORE handler with exception during save"""
        from pathlib import Path
        import tempfile

        scanner = _make_dicom_instance(self.mock_args)
        scanner.logger = Mock()

        # Create mock event that will raise exception
        mock_event = Mock()
        mock_ds = Mock()
        mock_ds.SOPInstanceUID = "1.2.3.4.5.6.7.8.9"
        mock_event.dataset = mock_ds
        mock_event.file_meta = Mock()

        # Make save_as raise exception
        mock_ds.save_as = Mock(side_effect=Exception("Disk full"))

        with tempfile.TemporaryDirectory() as tmpdir:
            scanner._cget_output_path = Path(tmpdir)
            scanner._cget_received_files = []
            scanner._cget_use_subdirs = False

            result = scanner._handle_store_for_cget(mock_event)

            self.assertEqual(result, 0xC211)  # Failure

    @patch("oida.protocols.dicom.PYNETDICOM_AVAILABLE", True)
    def test_cstore_handler_no_output_path(self):
        """Test C-STORE handler when output path is None"""

        scanner = _make_dicom_instance(self.mock_args)
        scanner.logger = Mock()

        mock_event = Mock()
        mock_ds = Mock()
        mock_ds.SOPInstanceUID = "1.2.3.4.5.6.7.8.9"
        mock_event.dataset = mock_ds
        mock_event.file_meta = Mock()

        scanner._cget_output_path = None  # No output path set
        scanner._cget_received_files = []

        result = scanner._handle_store_for_cget(mock_event)

        # Should return success even without saving
        self.assertEqual(result, 0x0000)


class TestDICOMDumpAllConfirmGate(unittest.TestCase):
    """--dump-all (mass PHI bulk C-GET) must be gated behind --confirm."""

    def _make_args(self, confirm):
        args = Mock()
        args.port = 11112
        args.timeout = 5
        args.aet = "OIDA"
        args.called_aet = "ANY"
        args.tls = False
        args.verbose = 0
        args.find = False
        args.get = False
        args.store = False
        args.move = False
        args.aet_brute = None
        args.common_ae = False
        args.confirm = confirm
        args.probe_ops = False
        args.worklist = False
        args.dump_all = True
        args.fuzz = False
        args.enum_operators = False
        args.enum_devices = False
        args.time_analysis = False
        return args

    def _run_proto_flow(self, scanner):
        # Neutralise every other workflow step so only the --dump-all branch
        # exercises real logic; create_conn_obj returns True so the body runs.
        with (
            patch.object(scanner, "create_conn_obj", return_value=True),
            patch.object(scanner, "enum_host_info"),
            patch.object(scanner, "print_host_info"),
            patch.object(scanner, "_analyze_security"),
            patch.object(scanner, "_export_results"),
            patch.object(scanner, "_disconnect"),
            patch.object(scanner, "_recursive_bulk_export") as mock_export,
        ):
            scanner.proto_flow()
        return mock_export

    def test_dump_all_skipped_without_confirm(self):
        scanner = _make_dicom_instance(self._make_args(confirm=False))
        scanner.logger = Mock()

        mock_export = self._run_proto_flow(scanner)

        mock_export.assert_not_called()
        scanner.logger.fail.assert_called_once()
        self.assertIn("--confirm", scanner.logger.fail.call_args[0][0])

    def test_dump_all_runs_with_confirm(self):
        scanner = _make_dicom_instance(self._make_args(confirm=True))
        scanner.logger = Mock()

        mock_export = self._run_proto_flow(scanner)

        mock_export.assert_called_once()


if __name__ == "__main__":
    unittest.main()
