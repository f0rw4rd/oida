#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for HL7 CLI options validation.

Tests all HL7 command-line options for:
- Argparse choice validation (invalid values)
- Required patient data enforcement for ADT/ORM/SIU
- Dangerous operation confirmation (--confirm)
- Port/timeout validation
- File options error handling
- Help output completeness
"""

import subprocess
import sys
import unittest
from unittest.mock import Mock, patch

from tests.unit.hl7.conftest import _make_hl7_instance


class TestHL7HelpOutput(unittest.TestCase):
    """Test HL7 help output shows all options correctly"""

    def test_help_output_contains_protocol_name(self):
        """Test --help shows HL7 protocol info"""
        result = subprocess.run(
            [sys.executable, "-m", "oida", "hl7", "--help"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        self.assertEqual(result.returncode, 0)
        self.assertIn("hl7", result.stdout.lower())

    def test_help_output_contains_message_operations(self):
        """Test --help shows message operations"""
        result = subprocess.run(
            [sys.executable, "-m", "oida", "hl7", "--help"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        output = result.stdout

        # Message operation options
        self.assertIn("--send-adt", output)
        self.assertIn("--send-orm", output)
        self.assertIn("--send-oru", output)
        self.assertIn("--send-qry", output)
        self.assertIn("--send-siu", output)
        self.assertIn("--send-mdm", output)
        self.assertIn("--send-rx", output)

    def test_help_output_contains_patient_options(self):
        """Test --help shows patient data options"""
        result = subprocess.run(
            [sys.executable, "-m", "oida", "hl7", "--help"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        output = result.stdout

        # Patient data options
        self.assertIn("--patient-id", output)
        self.assertIn("--patient-name", output)
        self.assertIn("--patient-dob", output)
        self.assertIn("--patient-sex", output)

    def test_help_output_contains_hl7_options(self):
        """Test --help shows HL7-specific options"""
        result = subprocess.run(
            [sys.executable, "-m", "oida", "hl7", "--help"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        output = result.stdout

        # HL7 options
        self.assertIn("--hl7-version", output)
        self.assertIn("--sending-app", output)
        self.assertIn("--sending-facility", output)
        self.assertIn("--adt-trigger", output)

    def test_help_output_contains_enumeration_options(self):
        """Test --help shows enumeration options"""
        result = subprocess.run(
            [sys.executable, "-m", "oida", "hl7", "--help"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        output = result.stdout

        # Enumeration options
        self.assertIn("--enum-all", output)
        self.assertIn("--enum-providers", output)
        self.assertIn("--enum-apps", output)
        self.assertIn("--enum-locations", output)
        self.assertIn("--enum-patients", output)


class TestHL7ChoiceValidation(unittest.TestCase):
    """Test argparse choice validation for invalid values"""

    def test_invalid_hl7_version(self):
        """Test invalid HL7 version is rejected"""
        result = subprocess.run(
            [sys.executable, "-m", "oida", "hl7", "127.0.0.1", "--hl7-version", "3.0"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        self.assertNotEqual(result.returncode, 0)
        # Should show valid choices in error message
        self.assertIn("invalid choice", result.stderr.lower())

    def test_valid_hl7_versions(self):
        """Test all valid HL7 versions are accepted by argparse"""
        valid_versions = ["2.1", "2.2", "2.3", "2.3.1", "2.4", "2.5", "2.5.1", "2.6", "2.7"]

        for version in valid_versions:
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "oida",
                    "hl7",
                    "127.0.0.1",
                    "--hl7-version",
                    version,
                    "--help",
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            # --help should return 0 if argparse accepted the version
            self.assertEqual(
                result.returncode, 0, f"HL7 version {version} should be valid: {result.stderr}"
            )

    def test_invalid_adt_trigger(self):
        """Test invalid ADT trigger event is rejected"""
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "oida",
                "hl7",
                "127.0.0.1",
                "--send-adt",
                "--patient-id",
                "X",
                "--adt-trigger",
                "A99",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invalid choice", result.stderr.lower())

    def test_valid_adt_triggers(self):
        """Test all valid ADT triggers are accepted by argparse"""
        valid_triggers = ["A01", "A02", "A03", "A04", "A08", "A11", "A13", "A31", "A40"]

        for trigger in valid_triggers:
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "oida",
                    "hl7",
                    "127.0.0.1",
                    "--adt-trigger",
                    trigger,
                    "--help",
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(
                result.returncode, 0, f"ADT trigger {trigger} should be valid: {result.stderr}"
            )

    def test_invalid_patient_sex(self):
        """Test invalid patient sex is rejected"""
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "oida",
                "hl7",
                "127.0.0.1",
                "--send-adt",
                "--patient-id",
                "X",
                "--patient-sex",
                "X",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invalid choice", result.stderr.lower())

    def test_valid_patient_sex(self):
        """Test all valid patient sex values are accepted"""
        valid_sex = ["M", "F", "O", "U"]

        for sex in valid_sex:
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "oida",
                    "hl7",
                    "127.0.0.1",
                    "--patient-sex",
                    sex,
                    "--help",
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(
                result.returncode, 0, f"Patient sex {sex} should be valid: {result.stderr}"
            )

    def test_invalid_patient_class(self):
        """Test invalid patient class is rejected"""
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "oida",
                "hl7",
                "127.0.0.1",
                "--send-adt",
                "--patient-id",
                "X",
                "--patient-class",
                "Z",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invalid choice", result.stderr.lower())

    def test_valid_patient_class(self):
        """Test all valid patient class values are accepted"""
        valid_class = ["I", "O", "E", "P", "R"]

        for cls in valid_class:
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "oida",
                    "hl7",
                    "127.0.0.1",
                    "--patient-class",
                    cls,
                    "--help",
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(
                result.returncode, 0, f"Patient class {cls} should be valid: {result.stderr}"
            )

    def test_invalid_order_priority(self):
        """Test invalid order priority is rejected"""
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "oida",
                "hl7",
                "127.0.0.1",
                "--send-orm",
                "--patient-id",
                "X",
                "--order-priority",
                "X",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invalid choice", result.stderr.lower())

    def test_valid_order_priority(self):
        """Test all valid order priority values are accepted"""
        valid_priority = ["S", "A", "R", "P", "T"]

        for pri in valid_priority:
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "oida",
                    "hl7",
                    "127.0.0.1",
                    "--order-priority",
                    pri,
                    "--help",
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(
                result.returncode, 0, f"Order priority {pri} should be valid: {result.stderr}"
            )

    def test_invalid_obx_type(self):
        """Test invalid OBX value type is rejected"""
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "oida",
                "hl7",
                "127.0.0.1",
                "--send-oru",
                "--obx-type",
                "XX",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invalid choice", result.stderr.lower())

    def test_valid_obx_type(self):
        """Test all valid OBX value types are accepted"""
        valid_types = ["NM", "ST", "TX", "CE", "DT", "TM"]

        for obx_type in valid_types:
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "oida",
                    "hl7",
                    "127.0.0.1",
                    "--obx-type",
                    obx_type,
                    "--help",
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(
                result.returncode, 0, f"OBX type {obx_type} should be valid: {result.stderr}"
            )

    def test_invalid_dx_type(self):
        """Test invalid diagnosis type is rejected"""
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "oida",
                "hl7",
                "127.0.0.1",
                "--send-adt",
                "--patient-id",
                "X",
                "--dx-type",
                "X",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invalid choice", result.stderr.lower())

    def test_valid_dx_type(self):
        """Test all valid diagnosis types are accepted"""
        valid_types = ["A", "W", "F"]

        for dx_type in valid_types:
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "oida",
                    "hl7",
                    "127.0.0.1",
                    "--dx-type",
                    dx_type,
                    "--help",
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(
                result.returncode, 0, f"DX type {dx_type} should be valid: {result.stderr}"
            )


class TestHL7RequiredPatientData(unittest.TestCase):
    """Test that ADT/ORM/SIU fail without required patient data"""

    @patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
    def test_adt_requires_patient_data(self):
        """Test ADT fails without patient ID or name"""

        mock_args = Mock()
        mock_args.port = 2575
        mock_args.timeout = 10
        mock_args.tls = False
        mock_args.verbose = 0
        mock_args.hl7_version = "2.5"
        mock_args.sending_app = "OIDA"
        mock_args.sending_facility = "SECURITY"
        mock_args.send_adt = True
        mock_args.send_oru = False
        mock_args.send_orm = False
        mock_args.send_rx = False
        mock_args.send_siu = False
        mock_args.send_qry = False
        mock_args.send_mdm = False
        mock_args.message_type = None
        mock_args.fuzz = False
        mock_args.confirm = False
        mock_args.enum_all = False
        mock_args.enum_providers = False
        mock_args.enum_apps = False
        mock_args.enum_locations = False
        mock_args.probe_ops = False
        mock_args.output = None
        mock_args.adt_trigger = "A01"
        mock_args.patient_id = None  # No patient ID
        mock_args.patient_name = None  # No patient name
        mock_args.mrn = None
        mock_args.patient_dob = ""
        mock_args.patient_sex = None
        mock_args.patient_address = ""
        mock_args.patient_phone = ""
        mock_args.visit_number = None
        mock_args.patient_class = None
        mock_args.admit_date = ""
        mock_args.location = ""
        mock_args.dx_code = None
        mock_args.dx_description = None
        mock_args.dx_type = "A"
        mock_args.dx_priority = "1"
        mock_args.dx_clinician = ""
        mock_args.pr_code = None
        mock_args.pr_description = None
        mock_args.pr_type = ""
        mock_args.pr_practitioner = ""

        scanner = _make_hl7_instance(mock_args, None, "192.168.1.100")
        scanner.logger = Mock()
        scanner.conn = Mock()  # Mock connection

        # Create message with segments should return None when patient data is required
        result = scanner._create_message_with_segments("ADT", "A01")

        # Should return None when patient data is missing
        self.assertIsNone(result)

    @patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
    def test_adt_succeeds_with_patient_id(self):
        """Test ADT succeeds with patient ID"""

        mock_args = Mock()
        mock_args.port = 2575
        mock_args.timeout = 10
        mock_args.tls = False
        mock_args.verbose = 0
        mock_args.hl7_version = "2.5"
        mock_args.sending_app = "OIDA"
        mock_args.sending_facility = "SECURITY"
        mock_args.patient_id = "PT001"  # Has patient ID
        mock_args.patient_name = None
        mock_args.mrn = None
        mock_args.patient_dob = ""
        mock_args.patient_sex = None
        mock_args.patient_address = ""
        mock_args.patient_phone = ""
        mock_args.visit_number = None
        mock_args.patient_class = None
        mock_args.admit_date = ""
        mock_args.location = ""
        mock_args.order_id = None
        mock_args.order_code = None
        mock_args.order_priority = "R"
        mock_args.obx_value = None
        mock_args.obx_id = None
        mock_args.obx_type = "NM"
        mock_args.obx_units = "mg/dL"
        mock_args.dx_code = None
        mock_args.dx_description = None
        mock_args.dx_type = "A"
        mock_args.dx_priority = "1"
        mock_args.dx_clinician = ""
        mock_args.pr_code = None
        mock_args.pr_description = None
        mock_args.pr_type = ""
        mock_args.pr_practitioner = ""
        mock_args.send_adt = False
        mock_args.send_oru = False
        mock_args.send_orm = False
        mock_args.send_rx = False
        mock_args.send_siu = False
        mock_args.send_qry = False
        mock_args.send_mdm = False
        mock_args.message_type = None
        mock_args.fuzz = False
        mock_args.confirm = False
        mock_args.enum_all = False
        mock_args.enum_providers = False
        mock_args.enum_apps = False
        mock_args.enum_locations = False
        mock_args.probe_ops = False
        mock_args.output = None

        scanner = _make_hl7_instance(mock_args, None, "192.168.1.100")
        scanner.logger = Mock()

        result = scanner._create_message_with_segments("ADT", "A01")

        # Should succeed with patient ID
        self.assertIsNotNone(result)
        self.assertIn("MSH", result)

    @patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
    def test_orm_requires_patient_data(self):
        """Test ORM fails without patient data"""

        mock_args = Mock()
        mock_args.port = 2575
        mock_args.timeout = 10
        mock_args.tls = False
        mock_args.verbose = 0
        mock_args.hl7_version = "2.5"
        mock_args.sending_app = "OIDA"
        mock_args.sending_facility = "SECURITY"
        mock_args.patient_id = None  # No patient ID
        mock_args.patient_name = None  # No patient name
        mock_args.mrn = None
        mock_args.patient_dob = ""
        mock_args.patient_sex = None
        mock_args.patient_address = ""
        mock_args.patient_phone = ""
        mock_args.visit_number = None
        mock_args.patient_class = None
        mock_args.admit_date = ""
        mock_args.location = ""
        mock_args.order_id = "ORD001"
        mock_args.order_code = "CBC"
        mock_args.order_priority = "R"
        mock_args.obx_value = None
        mock_args.obx_id = None
        mock_args.obx_type = "NM"
        mock_args.obx_units = "mg/dL"
        mock_args.dx_code = None
        mock_args.dx_description = None
        mock_args.dx_type = "A"
        mock_args.dx_priority = "1"
        mock_args.dx_clinician = ""
        mock_args.pr_code = None
        mock_args.pr_description = None
        mock_args.pr_type = ""
        mock_args.pr_practitioner = ""
        mock_args.send_adt = False
        mock_args.send_oru = False
        mock_args.send_orm = False
        mock_args.send_rx = False
        mock_args.send_siu = False
        mock_args.send_qry = False
        mock_args.send_mdm = False
        mock_args.message_type = None
        mock_args.fuzz = False
        mock_args.confirm = False
        mock_args.enum_all = False
        mock_args.enum_providers = False
        mock_args.enum_apps = False
        mock_args.enum_locations = False
        mock_args.probe_ops = False
        mock_args.output = None

        scanner = _make_hl7_instance(mock_args, None, "192.168.1.100")
        scanner.logger = Mock()

        result = scanner._create_message_with_segments("ORM", "O01")

        # Should return None when patient data is missing
        self.assertIsNone(result)

    @patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
    def test_siu_requires_patient_data(self):
        """Test SIU fails without patient data"""

        mock_args = Mock()
        mock_args.port = 2575
        mock_args.timeout = 10
        mock_args.tls = False
        mock_args.verbose = 0
        mock_args.hl7_version = "2.5"
        mock_args.sending_app = "OIDA"
        mock_args.sending_facility = "SECURITY"
        mock_args.patient_id = None  # No patient ID
        mock_args.patient_name = None  # No patient name
        mock_args.mrn = None
        mock_args.patient_dob = ""
        mock_args.patient_sex = None
        mock_args.patient_address = ""
        mock_args.patient_phone = ""
        mock_args.visit_number = None
        mock_args.patient_class = None
        mock_args.admit_date = ""
        mock_args.location = ""
        mock_args.order_id = None
        mock_args.order_code = None
        mock_args.order_priority = "R"
        mock_args.obx_value = None
        mock_args.obx_id = None
        mock_args.obx_type = "NM"
        mock_args.obx_units = "mg/dL"
        mock_args.dx_code = None
        mock_args.dx_description = None
        mock_args.dx_type = "A"
        mock_args.dx_priority = "1"
        mock_args.dx_clinician = ""
        mock_args.pr_code = None
        mock_args.pr_description = None
        mock_args.pr_type = ""
        mock_args.pr_practitioner = ""
        mock_args.send_adt = False
        mock_args.send_oru = False
        mock_args.send_orm = False
        mock_args.send_rx = False
        mock_args.send_siu = False
        mock_args.send_qry = False
        mock_args.send_mdm = False
        mock_args.message_type = None
        mock_args.fuzz = False
        mock_args.confirm = False
        mock_args.enum_all = False
        mock_args.enum_providers = False
        mock_args.enum_apps = False
        mock_args.enum_locations = False
        mock_args.probe_ops = False
        mock_args.output = None

        scanner = _make_hl7_instance(mock_args, None, "192.168.1.100")
        scanner.logger = Mock()

        result = scanner._create_message_with_segments("SIU", "S12")

        # Should return None when patient data is missing
        self.assertIsNone(result)

    @patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
    def test_oru_requires_patient_data(self):
        """Test ORU fails without patient data"""

        mock_args = Mock()
        mock_args.port = 2575
        mock_args.timeout = 10
        mock_args.tls = False
        mock_args.verbose = 0
        mock_args.hl7_version = "2.5"
        mock_args.sending_app = "OIDA"
        mock_args.sending_facility = "SECURITY"
        mock_args.patient_id = None  # No patient ID
        mock_args.patient_name = None  # No patient name
        mock_args.mrn = None
        mock_args.patient_dob = ""
        mock_args.patient_sex = None
        mock_args.patient_address = ""
        mock_args.patient_phone = ""
        mock_args.visit_number = None
        mock_args.patient_class = None
        mock_args.admit_date = ""
        mock_args.location = ""
        mock_args.order_id = None
        mock_args.order_code = None
        mock_args.order_priority = "R"
        mock_args.obx_value = "100"
        mock_args.obx_id = "GLU"
        mock_args.obx_type = "NM"
        mock_args.obx_units = "mg/dL"
        mock_args.dx_code = None
        mock_args.dx_description = None
        mock_args.dx_type = "A"
        mock_args.dx_priority = "1"
        mock_args.dx_clinician = ""
        mock_args.pr_code = None
        mock_args.pr_description = None
        mock_args.pr_type = ""
        mock_args.pr_practitioner = ""
        mock_args.send_adt = False
        mock_args.send_oru = False
        mock_args.send_orm = False
        mock_args.send_rx = False
        mock_args.send_siu = False
        mock_args.send_qry = False
        mock_args.send_mdm = False
        mock_args.message_type = None
        mock_args.fuzz = False
        mock_args.confirm = False
        mock_args.enum_all = False
        mock_args.enum_providers = False
        mock_args.enum_apps = False
        mock_args.enum_locations = False
        mock_args.probe_ops = False
        mock_args.output = None

        scanner = _make_hl7_instance(mock_args, None, "192.168.1.100")
        scanner.logger = Mock()

        result = scanner._create_message_with_segments("ORU", "R01")

        # Should return None when patient data is missing
        self.assertIsNone(result)


class TestHL7WriteOperationsRequireConfirm(unittest.TestCase):
    """Test all write operations require --confirm"""

    def _create_mock_args(self):
        """Create mock args with common defaults"""
        mock_args = Mock()
        mock_args.port = 2575
        mock_args.timeout = 10
        mock_args.tls = False
        mock_args.verbose = 0
        mock_args.hl7_version = "2.5"
        mock_args.sending_app = "OIDA"
        mock_args.sending_facility = "SECURITY"
        mock_args.patient_id = "PT001"
        mock_args.patient_name = "DOE^JOHN"
        mock_args.mrn = None
        mock_args.patient_dob = ""
        mock_args.patient_sex = "M"
        mock_args.patient_address = ""
        mock_args.patient_phone = ""
        mock_args.visit_number = None
        mock_args.patient_class = None
        mock_args.admit_date = ""
        mock_args.location = ""
        mock_args.adt_trigger = "A01"
        mock_args.confirm = False  # No confirmation
        mock_args.dx_code = None
        mock_args.dx_description = None
        mock_args.dx_type = "A"
        mock_args.dx_priority = "1"
        mock_args.dx_clinician = ""
        mock_args.pr_code = None
        mock_args.pr_description = None
        mock_args.pr_type = ""
        mock_args.pr_practitioner = ""
        mock_args.send_adt = False
        mock_args.send_oru = False
        mock_args.send_orm = False
        mock_args.send_rx = False
        mock_args.send_siu = False
        mock_args.send_qry = False
        mock_args.send_mdm = False
        mock_args.message_type = None
        mock_args.fuzz = False
        mock_args.enum_all = False
        mock_args.enum_patients = False
        mock_args.enum_providers = False
        mock_args.enum_apps = False
        mock_args.enum_locations = False
        mock_args.probe_ops = False
        mock_args.output = None
        return mock_args

    @patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
    def test_adt_requires_confirm(self):
        """Test ADT (all triggers) requires --confirm"""

        mock_args = self._create_mock_args()

        scanner = _make_hl7_instance(mock_args, None, "192.168.1.100")
        scanner.logger = Mock()
        scanner.conn = Mock()

        scanner._send_adt_message()

        # Should call logger.fail with message about --confirm
        scanner.logger.fail.assert_called()
        fail_args = str(scanner.logger.fail.call_args)
        self.assertIn("--confirm", fail_args)

    @patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
    def test_orm_requires_confirm(self):
        """Test ORM (Order) requires --confirm"""

        mock_args = self._create_mock_args()

        scanner = _make_hl7_instance(mock_args, None, "192.168.1.100")
        scanner.logger = Mock()
        scanner.conn = Mock()

        scanner._send_orm_message()

        # Should call logger.fail with message about --confirm
        scanner.logger.fail.assert_called()
        fail_args = str(scanner.logger.fail.call_args)
        self.assertIn("--confirm", fail_args)

    @patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
    def test_oru_requires_confirm(self):
        """Test ORU (Observation Result) requires --confirm"""

        mock_args = self._create_mock_args()

        scanner = _make_hl7_instance(mock_args, None, "192.168.1.100")
        scanner.logger = Mock()
        scanner.conn = Mock()

        scanner._send_oru_message()

        # Should call logger.fail with message about --confirm
        scanner.logger.fail.assert_called()
        fail_args = str(scanner.logger.fail.call_args)
        self.assertIn("--confirm", fail_args)

    @patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
    def test_siu_requires_confirm(self):
        """Test SIU (Scheduling) requires --confirm"""

        mock_args = self._create_mock_args()

        scanner = _make_hl7_instance(mock_args, None, "192.168.1.100")
        scanner.logger = Mock()
        scanner.conn = Mock()

        scanner._send_siu_message()

        # Should call logger.fail with message about --confirm
        scanner.logger.fail.assert_called()
        fail_args = str(scanner.logger.fail.call_args)
        self.assertIn("--confirm", fail_args)

    @patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
    def test_mdm_requires_confirm(self):
        """Test MDM (Document) requires --confirm"""

        mock_args = self._create_mock_args()

        scanner = _make_hl7_instance(mock_args, None, "192.168.1.100")
        scanner.logger = Mock()
        scanner.conn = Mock()

        scanner._send_mdm_message()

        # Should call logger.fail with message about --confirm
        scanner.logger.fail.assert_called()
        fail_args = str(scanner.logger.fail.call_args)
        self.assertIn("--confirm", fail_args)

    @patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
    def test_rx_requires_confirm(self):
        """Test RDE^O11 (Pharmacy Order) requires --confirm"""

        mock_args = self._create_mock_args()
        mock_args.rx_drug = "Amoxicillin"
        mock_args.rx_code = ""
        mock_args.rx_dose = "500"
        mock_args.rx_units = "mg"
        mock_args.rx_route = "PO"
        mock_args.rx_instructions = ""
        mock_args.rx_quantity = "30"
        mock_args.rx_refills = "0"
        mock_args.rx_provider = ""

        scanner = _make_hl7_instance(mock_args, None, "192.168.1.100")
        scanner.logger = Mock()
        scanner.conn = Mock()

        scanner._send_rx_message()

        # Should call logger.fail with message about --confirm
        scanner.logger.fail.assert_called()
        fail_args = str(scanner.logger.fail.call_args)
        self.assertIn("--confirm", fail_args)

    @patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
    def test_custom_message_requires_confirm(self):
        """Test custom message type requires --confirm"""

        mock_args = self._create_mock_args()

        scanner = _make_hl7_instance(mock_args, None, "192.168.1.100")
        scanner.logger = Mock()
        scanner.conn = Mock()

        scanner._send_custom_message("BAR^P01")

        # Should call logger.fail with message about --confirm
        scanner.logger.fail.assert_called()
        fail_args = str(scanner.logger.fail.call_args)
        self.assertIn("--confirm", fail_args)


class TestHL7PortTimeoutValidation(unittest.TestCase):
    """Test port and timeout validation"""

    def test_invalid_port_non_numeric(self):
        """Test non-numeric port is rejected by argparse"""
        result = subprocess.run(
            [sys.executable, "-m", "oida", "hl7", "127.0.0.1", "-p", "abc"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        # Should fail at argparse level
        self.assertNotEqual(result.returncode, 0)
        # Argparse should show error
        self.assertTrue("invalid" in result.stderr.lower() or "error" in result.stderr.lower())

    def test_invalid_timeout_non_numeric(self):
        """Test non-numeric timeout is rejected by argparse"""
        result = subprocess.run(
            [sys.executable, "-m", "oida", "hl7", "127.0.0.1", "--timeout", "abc"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        # Should fail at argparse level
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue("invalid" in result.stderr.lower() or "error" in result.stderr.lower())

    def test_port_type_is_int(self):
        """Test port argument is parsed as integer"""
        from oida.protocols.hl7.proto_args import proto_args
        from argparse import ArgumentParser

        parent_parser = ArgumentParser(add_help=False)
        main_parser = ArgumentParser()
        subparsers = main_parser.add_subparsers()

        hl7_parser = proto_args(subparsers, [parent_parser])
        args = hl7_parser.parse_args(["127.0.0.1", "-p", "2575"])

        self.assertIsInstance(args.port, int)
        self.assertEqual(args.port, 2575)

    def test_timeout_type_is_int(self):
        """Test timeout argument is parsed as integer"""
        from oida.protocols.hl7.proto_args import proto_args
        from argparse import ArgumentParser

        parent_parser = ArgumentParser(add_help=False)
        main_parser = ArgumentParser()
        subparsers = main_parser.add_subparsers()

        hl7_parser = proto_args(subparsers, [parent_parser])
        args = hl7_parser.parse_args(["127.0.0.1", "--timeout", "30"])

        self.assertIsInstance(args.timeout, int)
        self.assertEqual(args.timeout, 30)

    def test_port_default_value(self):
        """Test default port is 2575 for HL7"""
        from oida.protocols.hl7.proto_args import proto_args
        from argparse import ArgumentParser

        parent_parser = ArgumentParser(add_help=False)
        main_parser = ArgumentParser()
        subparsers = main_parser.add_subparsers()

        hl7_parser = proto_args(subparsers, [parent_parser])
        args = hl7_parser.parse_args(["127.0.0.1"])

        self.assertEqual(args.port, 2575)


class TestHL7FileOptions(unittest.TestCase):
    """Test file-related option validation"""

    def test_nonexistent_raw_file(self):
        """Test --send-raw with non-existent file fails gracefully"""
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "oida",
                "hl7",
                "127.0.0.1",
                "--send-raw",
                "/nonexistent/path/to/file.hl7",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        # Should not hang - either exit with error or handle gracefully
        # Connection will fail, but file error should be shown or handled
        self.assertNotEqual(result.returncode, -1)  # -1 would mean timeout/hang

    def test_nonexistent_output_directory(self):
        """Test -o with non-existent directory fails gracefully"""
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "oida",
                "hl7",
                "127.0.0.1",
                "-o",
                "/nonexistent/directory/path",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        # Should not hang
        self.assertNotEqual(result.returncode, -1)


class TestHL7ProtoArgsFactory(unittest.TestCase):
    """Test proto_args.py factory functions"""

    def test_proto_args_returns_parser(self):
        """Test proto_args() returns a valid parser"""
        from oida.protocols.hl7.proto_args import proto_args
        from argparse import ArgumentParser

        parent_parser = ArgumentParser(add_help=False)
        main_parser = ArgumentParser()
        subparsers = main_parser.add_subparsers()

        result = proto_args(subparsers, [parent_parser])

        self.assertIsNotNone(result)

    def test_proto_args_includes_message_operations(self):
        """Test proto_args includes message operation arguments"""
        from oida.protocols.hl7.proto_args import proto_args
        from argparse import ArgumentParser

        parent_parser = ArgumentParser(add_help=False)
        main_parser = ArgumentParser()
        subparsers = main_parser.add_subparsers()

        hl7_parser = proto_args(subparsers, [parent_parser])

        # Parse with message operations
        args = hl7_parser.parse_args(["127.0.0.1", "--send-adt"])

        self.assertTrue(args.send_adt)

    def test_proto_args_includes_patient_data(self):
        """Test proto_args includes patient data arguments"""
        from oida.protocols.hl7.proto_args import proto_args
        from argparse import ArgumentParser

        parent_parser = ArgumentParser(add_help=False)
        main_parser = ArgumentParser()
        subparsers = main_parser.add_subparsers()

        hl7_parser = proto_args(subparsers, [parent_parser])

        # Parse with patient data
        args = hl7_parser.parse_args(
            ["127.0.0.1", "--patient-id", "PT001", "--patient-name", "DOE^JOHN"]
        )

        self.assertEqual(args.patient_id, "PT001")
        self.assertEqual(args.patient_name, "DOE^JOHN")

    def test_proto_args_defaults(self):
        """Test proto_args sets correct defaults"""
        from oida.protocols.hl7.proto_args import proto_args
        from argparse import ArgumentParser

        parent_parser = ArgumentParser(add_help=False)
        main_parser = ArgumentParser()
        subparsers = main_parser.add_subparsers()

        hl7_parser = proto_args(subparsers, [parent_parser])

        args = hl7_parser.parse_args(["127.0.0.1"])

        # Check defaults
        self.assertEqual(args.hl7_version, "2.5")
        self.assertEqual(args.sending_app, "OIDA")
        self.assertEqual(args.sending_facility, "SECURITY")
        self.assertEqual(args.adt_trigger, "A01")
        self.assertEqual(args.order_priority, "R")
        self.assertEqual(args.obx_type, "NM")
        self.assertEqual(args.dx_type, "A")


class TestHL7ValidationScript(unittest.TestCase):
    """Run comprehensive validation tests as a script"""

    def test_validation_batch(self):
        """Run batch of validation tests"""
        tests = [
            # (name, args, should_fail)
            ("hl7-version invalid", ["--hl7-version", "3.0"], True),
            (
                "adt-trigger invalid",
                ["--send-adt", "--patient-id", "X", "--adt-trigger", "A99"],
                True,
            ),
            (
                "patient-sex invalid",
                ["--send-adt", "--patient-id", "X", "--patient-sex", "X"],
                True,
            ),
            (
                "patient-class invalid",
                ["--send-adt", "--patient-id", "X", "--patient-class", "Z"],
                True,
            ),
            (
                "order-priority invalid",
                ["--send-orm", "--patient-id", "X", "--order-priority", "X"],
                True,
            ),
            ("obx-type invalid", ["--send-oru", "--obx-type", "XX"], True),
            ("dx-type invalid", ["--send-adt", "--patient-id", "X", "--dx-type", "X"], True),
            # Valid options should pass argparse
            ("hl7-version valid 2.5", ["--hl7-version", "2.5", "--help"], False),
            ("adt-trigger valid A01", ["--adt-trigger", "A01", "--help"], False),
            ("patient-sex valid M", ["--patient-sex", "M", "--help"], False),
        ]

        results = []
        for name, extra_args, should_fail in tests:
            cmd = [sys.executable, "-m", "oida", "hl7", "127.0.0.1"] + extra_args
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            if should_fail:
                passed = result.returncode != 0
            else:
                passed = result.returncode == 0

            results.append((name, passed))

        # All tests should pass
        for name, passed in results:
            self.assertTrue(passed, f"Test '{name}' failed")


if __name__ == "__main__":
    unittest.main()
