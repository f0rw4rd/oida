#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for FHIR R4 protocol scanner functionality.

Tests the FHIR protocol scanner for:
- HTTP/HTTPS connection handling
- CapabilityStatement parsing
- Vendor identification
- Security assessment
"""

import unittest
from unittest.mock import Mock, patch


class TestFHIRConstants(unittest.TestCase):
    """Test FHIR constants and mappings"""

    def test_vendor_map_exists(self):
        """Test FHIR vendor map contains expected entries (uppercase keys)"""
        from oida.protocols.fhir import FHIR_VENDOR_MAP

        # Keys are uppercase in the actual implementation
        self.assertIn("EPIC", FHIR_VENDOR_MAP)
        self.assertIn("CERNER", FHIR_VENDOR_MAP)
        self.assertIn("HAPI", FHIR_VENDOR_MAP)
        self.assertIn("MICROSOFT", FHIR_VENDOR_MAP)
        self.assertIn("GOOGLE", FHIR_VENDOR_MAP)

    def test_vendor_map_values(self):
        """Test FHIR vendor map value structure"""
        from oida.protocols.fhir import FHIR_VENDOR_MAP

        # Check Epic entry
        epic = FHIR_VENDOR_MAP.get("EPIC")
        self.assertIsNotNone(epic)
        self.assertEqual(epic[0], "Epic Systems")
        self.assertEqual(epic[1], "Epic FHIR Server")

        # Check Cerner entry
        cerner = FHIR_VENDOR_MAP.get("CERNER")
        self.assertIsNotNone(cerner)
        self.assertEqual(cerner[0], "Cerner Corporation")

    def test_vendor_map_cloud_providers(self):
        """Test FHIR vendor map includes cloud providers"""
        from oida.protocols.fhir import FHIR_VENDOR_MAP

        self.assertIn("MICROSOFT", FHIR_VENDOR_MAP)
        self.assertIn("GOOGLE", FHIR_VENDOR_MAP)
        self.assertIn("AWS", FHIR_VENDOR_MAP)

    def test_vendor_map_open_source(self):
        """Test FHIR vendor map includes open source implementations"""
        from oida.protocols.fhir import FHIR_VENDOR_MAP

        self.assertIn("HAPI", FHIR_VENDOR_MAP)
        self.assertIn("LINUXFORHEALTH", FHIR_VENDOR_MAP)

    def test_vendor_map_value_structure(self):
        """Test vendor map values have correct structure"""
        from oida.protocols.fhir import FHIR_VENDOR_MAP

        for key, value in FHIR_VENDOR_MAP.items():
            self.assertIsInstance(value, tuple, f"Value for {key} is not a tuple")
            self.assertEqual(len(value), 2, f"Value for {key} doesn't have 2 elements")
            self.assertIsInstance(value[0], str, f"Vendor name for {key} is not a string")
            self.assertIsInstance(value[1], str, f"Product type for {key} is not a string")


class TestFHIRScannerInit(unittest.TestCase):
    """Test FHIR scanner initialization"""

    def setUp(self):
        """Set up test fixtures"""
        self.mock_args = Mock()
        self.mock_args.port = 443
        self.mock_args.timeout = 30
        self.mock_args.tls = True
        self.mock_args.tls_insecure = False
        self.mock_args.verbose = 0
        self.mock_args.debug = False
        self.mock_args.fhir_version = "R4"
        self.mock_args.caps = False
        self.mock_args.enum_all = False
        self.mock_args.token = None
        self.mock_args.username = None
        self.mock_args.password = None
        self.mock_args.client_id = None
        self.mock_args.client_secret = None
        self.mock_args.scope = None
        self.mock_args.auth_url = None
        self.mock_args.token_url = None
        self.mock_args.search_patients = False
        self.mock_args.search_observations = False
        self.mock_args.search_medications = False
        self.mock_args.search_conditions = False
        self.mock_args.search_encounters = False
        self.mock_args.search_procedures = False
        self.mock_args.search_allergies = False
        self.mock_args.search_immunizations = False
        self.mock_args.search_diagnostics = False
        self.mock_args.search_documents = False
        self.mock_args.patient_id = None
        self.mock_args.patient_name = None
        self.mock_args.patient_dob = None
        self.mock_args.patient_gender = None
        self.mock_args.max_results = 100
        self.mock_args.wildcard = False
        self.mock_args.date_from = None
        self.mock_args.date_to = None
        self.mock_args.code = None
        self.mock_args.category = None
        self.mock_args.read_patient = None
        self.mock_args.read_observation = None
        self.mock_args.read_medication = None
        self.mock_args.read_condition = None
        self.mock_args.read_encounter = None
        self.mock_args.test_auth = False
        self.mock_args.test_cross_patient = False
        self.mock_args.test_scope = False
        self.mock_args.bulk_export = False
        self.mock_args.bulk_export_type = "Patient"
        self.mock_args.confirm = False
        self.mock_args.include = None
        self.mock_args.revinclude = None
        self.mock_args.elements = None
        self.mock_args.summary = None
        self.mock_args.save_response = None
        self.mock_args.output = None
        self.mock_args.format = "csv,json"
        self.mock_args.brute = False
        self.mock_args.default_creds = False
        self.mock_args.wordlist = None
        self.mock_args.brute_rate = 0.5
        self.mock_args.continue_on_success = False
        self.mock_args.user_file = None
        self.mock_args.pass_file = None
        self.mock_args.brute_method = "basic"
        self.mock_args.credentials = None

    @patch("oida.protocols.fhir.is_fhirclient_available", return_value=True)
    def test_scanner_initialization(self, mock_available):
        """Test basic scanner initialization"""
        from oida.protocols.fhir import fhir

        scanner = fhir(self.mock_args, None, "https://fhir.example.com/r4")

        self.assertEqual(scanner.protocol_name, "fhir")
        self.assertEqual(scanner.default_port, 443)
        self.assertEqual(scanner.host, "https://fhir.example.com/r4")

    @patch("oida.protocols.fhir.is_fhirclient_available", return_value=True)
    def test_scanner_has_results_structure(self, mock_available):
        """Test scanner has proper results structure"""
        from oida.protocols.fhir import fhir

        scanner = fhir(self.mock_args, None, "https://fhir.example.com/r4")

        self.assertIn("data", scanner.results)
        self.assertIsInstance(scanner.results["data"], dict)


class TestFHIRVendorIdentification(unittest.TestCase):
    """Test FHIR vendor identification from CapabilityStatement"""

    def setUp(self):
        """Set up test fixtures"""
        self.mock_args = Mock()
        self.mock_args.port = 443
        self.mock_args.timeout = 30
        self.mock_args.tls = True
        self.mock_args.tls_insecure = False
        self.mock_args.verbose = 0
        self.mock_args.debug = False
        self.mock_args.fhir_version = "R4"
        self.mock_args.caps = False
        self.mock_args.enum_all = False
        self.mock_args.token = None
        self.mock_args.username = None
        self.mock_args.password = None
        self.mock_args.client_id = None
        self.mock_args.client_secret = None
        self.mock_args.scope = None
        self.mock_args.auth_url = None
        self.mock_args.token_url = None
        self.mock_args.search_patients = False
        self.mock_args.search_observations = False
        self.mock_args.search_medications = False
        self.mock_args.search_conditions = False
        self.mock_args.search_encounters = False
        self.mock_args.search_procedures = False
        self.mock_args.search_allergies = False
        self.mock_args.search_immunizations = False
        self.mock_args.search_diagnostics = False
        self.mock_args.search_documents = False
        self.mock_args.patient_id = None
        self.mock_args.patient_name = None
        self.mock_args.patient_dob = None
        self.mock_args.patient_gender = None
        self.mock_args.max_results = 100
        self.mock_args.wildcard = False
        self.mock_args.date_from = None
        self.mock_args.date_to = None
        self.mock_args.code = None
        self.mock_args.category = None
        self.mock_args.read_patient = None
        self.mock_args.read_observation = None
        self.mock_args.read_medication = None
        self.mock_args.read_condition = None
        self.mock_args.read_encounter = None
        self.mock_args.test_auth = False
        self.mock_args.test_cross_patient = False
        self.mock_args.test_scope = False
        self.mock_args.bulk_export = False
        self.mock_args.bulk_export_type = "Patient"
        self.mock_args.confirm = False
        self.mock_args.include = None
        self.mock_args.revinclude = None
        self.mock_args.elements = None
        self.mock_args.summary = None
        self.mock_args.save_response = None
        self.mock_args.output = None
        self.mock_args.format = "csv,json"
        self.mock_args.brute = False
        self.mock_args.default_creds = False
        self.mock_args.wordlist = None
        self.mock_args.brute_rate = 0.5
        self.mock_args.continue_on_success = False
        self.mock_args.user_file = None
        self.mock_args.pass_file = None
        self.mock_args.brute_method = "basic"
        self.mock_args.credentials = None

    @patch("oida.protocols.fhir.is_fhirclient_available", return_value=True)
    def test_identify_epic(self, mock_available):
        """Test Epic vendor identification"""
        from oida.protocols.fhir import fhir

        scanner = fhir(self.mock_args, None, "https://fhir.example.com/r4")
        # _identify_vendor takes two args: software_name, publisher
        vendor, product = scanner._identify_vendor("Epic Systems", "")

        self.assertEqual(vendor, "Epic Systems")
        self.assertEqual(product, "Epic FHIR Server")

    @patch("oida.protocols.fhir.is_fhirclient_available", return_value=True)
    def test_identify_cerner(self, mock_available):
        """Test Cerner vendor identification"""
        from oida.protocols.fhir import fhir

        scanner = fhir(self.mock_args, None, "https://fhir.example.com/r4")
        vendor, product = scanner._identify_vendor("Cerner Corporation", "")

        self.assertEqual(vendor, "Cerner Corporation")

    @patch("oida.protocols.fhir.is_fhirclient_available", return_value=True)
    def test_identify_hapi(self, mock_available):
        """Test HAPI FHIR identification"""
        from oida.protocols.fhir import fhir

        scanner = fhir(self.mock_args, None, "https://fhir.example.com/r4")
        vendor, product = scanner._identify_vendor("HAPI FHIR Server", "")

        self.assertEqual(vendor, "HAPI FHIR")
        self.assertEqual(product, "HAPI FHIR Server")

    @patch("oida.protocols.fhir.is_fhirclient_available", return_value=True)
    def test_identify_unknown_vendor(self, mock_available):
        """Test unknown vendor returns None"""
        from oida.protocols.fhir import fhir

        scanner = fhir(self.mock_args, None, "https://fhir.example.com/r4")
        vendor, product = scanner._identify_vendor("Unknown System", "")

        self.assertIsNone(vendor)
        self.assertIsNone(product)

    @patch("oida.protocols.fhir.is_fhirclient_available", return_value=True)
    def test_identify_from_publisher(self, mock_available):
        """Test vendor identification from publisher field"""
        from oida.protocols.fhir import fhir

        scanner = fhir(self.mock_args, None, "https://fhir.example.com/r4")
        vendor, product = scanner._identify_vendor("", "Firely")

        self.assertEqual(vendor, "Firely")
        self.assertEqual(product, "Vonk FHIR Server")


class TestFHIRSecurityModes(unittest.TestCase):
    """Test FHIR security mode constants"""

    def test_security_modes_exist(self):
        """Test FHIR security modes constant exists"""
        from oida.protocols.fhir import FHIR_SECURITY_MODES

        self.assertIn("none", FHIR_SECURITY_MODES)
        self.assertIsInstance(FHIR_SECURITY_MODES, dict)

    def test_security_modes_values(self):
        """Test FHIR security modes have string descriptions"""
        from oida.protocols.fhir import FHIR_SECURITY_MODES

        for key, value in FHIR_SECURITY_MODES.items():
            self.assertIsInstance(value, str, f"Value for {key} is not a string")


class TestFHIRAvailability(unittest.TestCase):
    """Test FHIR dependency availability checking"""

    def test_is_fhirclient_available_function(self):
        """Test is_fhirclient_available function exists"""
        from oida.protocols.fhir import is_fhirclient_available

        self.assertTrue(callable(is_fhirclient_available))

    def test_is_fhirclient_available_returns_bool(self):
        """Test is_fhirclient_available returns boolean"""
        from oida.protocols.fhir import is_fhirclient_available

        result = is_fhirclient_available()
        self.assertIsInstance(result, bool)


class TestFHIRBaseURL(unittest.TestCase):
    """Test FHIR base URL handling"""

    def setUp(self):
        """Set up test fixtures"""
        self.mock_args = Mock()
        self.mock_args.port = 443
        self.mock_args.timeout = 30
        self.mock_args.tls = True
        self.mock_args.tls_insecure = False
        self.mock_args.verbose = 0
        self.mock_args.debug = False
        self.mock_args.fhir_version = "R4"
        self.mock_args.caps = False
        self.mock_args.enum_all = False
        self.mock_args.token = None
        self.mock_args.username = None
        self.mock_args.password = None
        self.mock_args.client_id = None
        self.mock_args.client_secret = None
        self.mock_args.scope = None
        self.mock_args.auth_url = None
        self.mock_args.token_url = None
        self.mock_args.search_patients = False
        self.mock_args.search_observations = False
        self.mock_args.search_medications = False
        self.mock_args.search_conditions = False
        self.mock_args.search_encounters = False
        self.mock_args.search_procedures = False
        self.mock_args.search_allergies = False
        self.mock_args.search_immunizations = False
        self.mock_args.search_diagnostics = False
        self.mock_args.search_documents = False
        self.mock_args.patient_id = None
        self.mock_args.patient_name = None
        self.mock_args.patient_dob = None
        self.mock_args.patient_gender = None
        self.mock_args.max_results = 100
        self.mock_args.wildcard = False
        self.mock_args.date_from = None
        self.mock_args.date_to = None
        self.mock_args.code = None
        self.mock_args.category = None
        self.mock_args.read_patient = None
        self.mock_args.read_observation = None
        self.mock_args.read_medication = None
        self.mock_args.read_condition = None
        self.mock_args.read_encounter = None
        self.mock_args.test_auth = False
        self.mock_args.test_cross_patient = False
        self.mock_args.test_scope = False
        self.mock_args.bulk_export = False
        self.mock_args.bulk_export_type = "Patient"
        self.mock_args.confirm = False
        self.mock_args.include = None
        self.mock_args.revinclude = None
        self.mock_args.elements = None
        self.mock_args.summary = None
        self.mock_args.save_response = None
        self.mock_args.output = None
        self.mock_args.format = "csv,json"
        self.mock_args.brute = False
        self.mock_args.default_creds = False
        self.mock_args.wordlist = None
        self.mock_args.brute_rate = 0.5
        self.mock_args.continue_on_success = False
        self.mock_args.user_file = None
        self.mock_args.pass_file = None
        self.mock_args.brute_method = "basic"
        self.mock_args.credentials = None

    @patch("oida.protocols.fhir.is_fhirclient_available", return_value=True)
    def test_get_base_url_with_https(self, mock_available):
        """Test _get_base_url with full HTTPS URL"""
        from oida.protocols.fhir import fhir

        scanner = fhir(self.mock_args, None, "https://fhir.example.com/r4")
        base_url = scanner._get_base_url()

        self.assertEqual(base_url, "https://fhir.example.com/r4")

    @patch("oida.protocols.fhir.is_fhirclient_available", return_value=True)
    def test_get_base_url_strips_trailing_slash(self, mock_available):
        """Test _get_base_url strips trailing slash"""
        from oida.protocols.fhir import fhir

        scanner = fhir(self.mock_args, None, "https://fhir.example.com/r4/")
        base_url = scanner._get_base_url()

        self.assertEqual(base_url, "https://fhir.example.com/r4")


if __name__ == "__main__":
    unittest.main()
