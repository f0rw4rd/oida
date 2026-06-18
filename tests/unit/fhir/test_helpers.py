#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for FHIR helpers module.

Tests constants, lazy imports, and utility functions:
- validate_credential_path()
- _get_fhir_validation_error()
- is_fhirclient_available()
- FHIR_SECURITY_MODES constant
- FHIR_VENDOR_MAP structure
- Lazy import aliases
"""

import os
import unittest
from unittest.mock import patch


class TestValidateCredentialPath(unittest.TestCase):
    """Test validate_credential_path() function"""

    def test_simple_valid_path(self):
        """Test a simple valid path returns resolved absolute path"""
        from oida.protocols.fhir.helpers import validate_credential_path

        result = validate_credential_path("/tmp/creds.txt")
        self.assertEqual(result, os.path.realpath("/tmp/creds.txt"))

    def test_relative_path_resolves(self):
        """Test a relative path is resolved to absolute"""
        from oida.protocols.fhir.helpers import validate_credential_path

        result = validate_credential_path("creds.txt")
        self.assertTrue(os.path.isabs(result))

    def test_directory_traversal_relative(self):
        """Test relative path with .. is rejected"""
        from oida.protocols.fhir.helpers import validate_credential_path

        with self.assertRaises(ValueError) as ctx:
            validate_credential_path("../etc/shadow")
        self.assertIn("traversal", str(ctx.exception).lower())

    def test_directory_traversal_relative_nested(self):
        """Test relative nested traversal is blocked"""
        from oida.protocols.fhir.helpers import validate_credential_path

        with self.assertRaises(ValueError):
            validate_credential_path("../../etc/passwd")

    def test_directory_traversal_relative_in_middle(self):
        """Test relative traversal in middle of path is blocked"""
        from oida.protocols.fhir.helpers import validate_credential_path

        with self.assertRaises(ValueError):
            validate_credential_path("foo/../../etc/passwd")

    def test_absolute_path_with_double_dot_resolves(self):
        """Test absolute path with .. is resolved by normpath (not blocked)"""
        from oida.protocols.fhir.helpers import validate_credential_path

        # For absolute paths, normpath collapses .. so the function
        # accepts the resolved path
        result = validate_credential_path("/tmp/../tmp/creds.txt")
        self.assertTrue(os.path.isabs(result))

    def test_path_with_dot_is_allowed(self):
        """Test path with single dot (current dir) is allowed"""
        from oida.protocols.fhir.helpers import validate_credential_path

        result = validate_credential_path("/tmp/./creds.txt")
        self.assertTrue(os.path.isabs(result))

    def test_path_with_dotfile_is_allowed(self):
        """Test path with dotfile name (not traversal) is allowed"""
        from oida.protocols.fhir.helpers import validate_credential_path

        result = validate_credential_path("/tmp/.hidden_creds")
        self.assertTrue(os.path.isabs(result))

    def test_returns_string(self):
        """Test return type is string"""
        from oida.protocols.fhir.helpers import validate_credential_path

        result = validate_credential_path("/tmp/test")
        self.assertIsInstance(result, str)


class TestGetFHIRValidationError(unittest.TestCase):
    """Test _get_fhir_validation_error() function"""

    def test_returns_class(self):
        """Test it returns a class (not an instance)"""
        from oida.protocols.fhir.helpers import _get_fhir_validation_error

        result = _get_fhir_validation_error()
        self.assertTrue(isinstance(result, type))

    def test_returned_class_is_exception_subclass(self):
        """Test the returned class can be used for exception handling"""
        from oida.protocols.fhir.helpers import _get_fhir_validation_error

        err_class = _get_fhir_validation_error()
        self.assertTrue(issubclass(err_class, Exception))

    def test_returned_class_is_raisable(self):
        """Test the returned class can be raised and caught"""
        from oida.protocols.fhir.helpers import _get_fhir_validation_error

        err_class = _get_fhir_validation_error()
        with self.assertRaises(Exception):
            raise err_class("test error")

    def test_fallback_class_when_module_fails(self):
        """Test fallback class is returned when fhirabstractbase raises"""
        from oida.protocols.fhir.helpers import _get_fhir_validation_error

        # Create a plain object that raises on FHIRValidationError access
        class FailingModule:
            @property
            def FHIRValidationError(self):
                raise ImportError("module not available")

        with patch("oida.protocols.fhir.helpers._fhirabstractbase", FailingModule()):
            result = _get_fhir_validation_error()
            self.assertTrue(isinstance(result, type))
            self.assertTrue(issubclass(result, Exception))
            self.assertEqual(result.__name__, "FHIRValidationError")

    def test_fallback_class_is_raisable_from_fallback(self):
        """Test the dynamically-created fallback class works"""
        from oida.protocols.fhir.helpers import _get_fhir_validation_error

        class FailingModule:
            @property
            def FHIRValidationError(self):
                raise RuntimeError("unavailable")

        with patch("oida.protocols.fhir.helpers._fhirabstractbase", FailingModule()):
            err_class = _get_fhir_validation_error()
            with self.assertRaises(Exception):
                raise err_class("test error")


class TestIsFhirclientAvailable(unittest.TestCase):
    """Test is_fhirclient_available() function"""

    def test_returns_bool(self):
        """Test function returns a boolean"""
        from oida.protocols.fhir.helpers import is_fhirclient_available

        result = is_fhirclient_available()
        self.assertIsInstance(result, bool)

    def test_callable(self):
        """Test function is callable"""
        from oida.protocols.fhir.helpers import is_fhirclient_available

        self.assertTrue(callable(is_fhirclient_available))

    def test_consistent_results(self):
        """Test calling multiple times gives same result"""
        from oida.protocols.fhir.helpers import is_fhirclient_available

        result1 = is_fhirclient_available()
        result2 = is_fhirclient_available()
        self.assertEqual(result1, result2)


class TestFHIRSecurityModes(unittest.TestCase):
    """Test FHIR_SECURITY_MODES constant"""

    def test_has_six_modes(self):
        """Test there are exactly 6 security modes defined (1 none + 5 URL-based)"""
        from oida.protocols.fhir.helpers import FHIR_SECURITY_MODES

        self.assertEqual(len(FHIR_SECURITY_MODES), 6)

    def test_none_mode_exists(self):
        """Test 'none' mode is present"""
        from oida.protocols.fhir.helpers import FHIR_SECURITY_MODES

        self.assertIn("none", FHIR_SECURITY_MODES)
        self.assertEqual(FHIR_SECURITY_MODES["none"], "No security (anonymous access)")

    def test_all_values_are_strings(self):
        """Test all mode values are description strings"""
        from oida.protocols.fhir.helpers import FHIR_SECURITY_MODES

        for key, value in FHIR_SECURITY_MODES.items():
            self.assertIsInstance(key, str, f"Key {key!r} is not a string")
            self.assertIsInstance(value, str, f"Value for {key} is not a string")

    def test_security_base_url_in_keys(self):
        """Test security modes use proper HL7 CodeSystem URLs"""
        from oida.protocols.fhir.helpers import FHIR_SECURITY_MODES

        base = "http://terminology.hl7.org/CodeSystem/restful-security-service"
        url_keys = [k for k in FHIR_SECURITY_MODES if k.startswith(base)]
        self.assertEqual(len(url_keys), 5)

    def test_smart_on_fhir_mode(self):
        """Test SMART on FHIR mode is present"""
        from oida.protocols.fhir.helpers import FHIR_SECURITY_MODES

        smart_keys = [k for k in FHIR_SECURITY_MODES if "SMART" in k]
        self.assertEqual(len(smart_keys), 1)
        self.assertIn("SMART on FHIR", FHIR_SECURITY_MODES[smart_keys[0]])

    def test_oauth_mode(self):
        """Test OAuth mode is present"""
        from oida.protocols.fhir.helpers import FHIR_SECURITY_MODES

        oauth_keys = [k for k in FHIR_SECURITY_MODES if k.endswith("|OAuth")]
        self.assertEqual(len(oauth_keys), 1)

    def test_basic_auth_mode(self):
        """Test Basic auth mode is present"""
        from oida.protocols.fhir.helpers import FHIR_SECURITY_MODES

        basic_keys = [k for k in FHIR_SECURITY_MODES if k.endswith("|Basic")]
        self.assertEqual(len(basic_keys), 1)

    def test_ntlm_mode(self):
        """Test NTLM auth mode is present"""
        from oida.protocols.fhir.helpers import FHIR_SECURITY_MODES

        ntlm_keys = [k for k in FHIR_SECURITY_MODES if k.endswith("|NTLM")]
        self.assertEqual(len(ntlm_keys), 1)

    def test_certificates_mode(self):
        """Test Certificates mode is present"""
        from oida.protocols.fhir.helpers import FHIR_SECURITY_MODES

        cert_keys = [k for k in FHIR_SECURITY_MODES if k.endswith("|Certificates")]
        self.assertEqual(len(cert_keys), 1)


class TestFHIRVendorMap(unittest.TestCase):
    """Test FHIR_VENDOR_MAP structure and entries"""

    def test_all_entries_are_tuples(self):
        """Test every entry is a (vendor, product) tuple"""
        from oida.protocols.fhir.helpers import FHIR_VENDOR_MAP

        for key, value in FHIR_VENDOR_MAP.items():
            self.assertIsInstance(value, tuple, f"Value for {key} is not a tuple")
            self.assertEqual(len(value), 2, f"Tuple for {key} has wrong length")

    def test_all_values_are_strings(self):
        """Test both elements in each tuple are strings"""
        from oida.protocols.fhir.helpers import FHIR_VENDOR_MAP

        for key, (vendor, product) in FHIR_VENDOR_MAP.items():
            self.assertIsInstance(vendor, str, f"Vendor for {key} is not a string")
            self.assertIsInstance(product, str, f"Product for {key} is not a string")

    def test_all_keys_are_uppercase(self):
        """Test all vendor map keys are uppercase"""
        from oida.protocols.fhir.helpers import FHIR_VENDOR_MAP

        for key in FHIR_VENDOR_MAP:
            self.assertEqual(key, key.upper(), f"Key {key!r} is not uppercase")

    def test_major_emr_vendors(self):
        """Test major EMR vendors are present"""
        from oida.protocols.fhir.helpers import FHIR_VENDOR_MAP

        expected = ["EPIC", "CERNER", "MEDITECH", "ALLSCRIPTS", "ATHENA"]
        for vendor_key in expected:
            self.assertIn(vendor_key, FHIR_VENDOR_MAP, f"Missing {vendor_key}")

    def test_cloud_vendors(self):
        """Test cloud platform vendors are present"""
        from oida.protocols.fhir.helpers import FHIR_VENDOR_MAP

        expected = ["MICROSOFT", "AZURE", "GOOGLE", "AWS"]
        for vendor_key in expected:
            self.assertIn(vendor_key, FHIR_VENDOR_MAP, f"Missing {vendor_key}")

    def test_open_source_vendors(self):
        """Test open source FHIR servers are present"""
        from oida.protocols.fhir.helpers import FHIR_VENDOR_MAP

        expected = ["HAPI", "FIRELY", "VONK", "SPARK", "IBM"]
        for vendor_key in expected:
            self.assertIn(vendor_key, FHIR_VENDOR_MAP, f"Missing {vendor_key}")

    def test_no_empty_vendor_names(self):
        """Test no vendor names or product types are empty strings"""
        from oida.protocols.fhir.helpers import FHIR_VENDOR_MAP

        for key, (vendor, product) in FHIR_VENDOR_MAP.items():
            self.assertTrue(len(vendor) > 0, f"Empty vendor name for {key}")
            self.assertTrue(len(product) > 0, f"Empty product type for {key}")


class TestLazyImportAliases(unittest.TestCase):
    """Test lazy import aliases exist in helpers module"""

    def test_fhirclient_alias_exists(self):
        """Test fhirclient alias is defined"""
        from oida.protocols.fhir import helpers

        self.assertTrue(hasattr(helpers, "fhirclient"))

    def test_capabilitystatement_alias_exists(self):
        """Test capabilitystatement alias is defined"""
        from oida.protocols.fhir import helpers

        self.assertTrue(hasattr(helpers, "capabilitystatement"))

    def test_patient_alias_exists(self):
        """Test patient alias is defined"""
        from oida.protocols.fhir import helpers

        self.assertTrue(hasattr(helpers, "patient"))

    def test_observation_alias_exists(self):
        """Test observation alias is defined"""
        from oida.protocols.fhir import helpers

        self.assertTrue(hasattr(helpers, "observation"))

    def test_medicationrequest_alias_exists(self):
        """Test medicationrequest alias is defined"""
        from oida.protocols.fhir import helpers

        self.assertTrue(hasattr(helpers, "medicationrequest"))

    def test_condition_alias_exists(self):
        """Test condition alias is defined"""
        from oida.protocols.fhir import helpers

        self.assertTrue(hasattr(helpers, "condition"))

    def test_encounter_alias_exists(self):
        """Test encounter alias is defined"""
        from oida.protocols.fhir import helpers

        self.assertTrue(hasattr(helpers, "encounter"))

    def test_procedure_alias_exists(self):
        """Test procedure alias is defined"""
        from oida.protocols.fhir import helpers

        self.assertTrue(hasattr(helpers, "procedure"))

    def test_practitioner_alias_exists(self):
        """Test practitioner alias is defined"""
        from oida.protocols.fhir import helpers

        self.assertTrue(hasattr(helpers, "practitioner"))

    def test_organization_alias_exists(self):
        """Test organization alias is defined"""
        from oida.protocols.fhir import helpers

        self.assertTrue(hasattr(helpers, "organization"))

    def test_location_alias_exists(self):
        """Test location alias is defined"""
        from oida.protocols.fhir import helpers

        self.assertTrue(hasattr(helpers, "location"))

    def test_device_alias_exists(self):
        """Test device alias is defined"""
        from oida.protocols.fhir import helpers

        self.assertTrue(hasattr(helpers, "device"))

    def test_servicerequest_alias_exists(self):
        """Test servicerequest alias is defined"""
        from oida.protocols.fhir import helpers

        self.assertTrue(hasattr(helpers, "servicerequest"))

    def test_allergyintolerance_alias_exists(self):
        """Test allergyintolerance alias is defined"""
        from oida.protocols.fhir import helpers

        self.assertTrue(hasattr(helpers, "allergyintolerance"))

    def test_immunization_alias_exists(self):
        """Test immunization alias is defined"""
        from oida.protocols.fhir import helpers

        self.assertTrue(hasattr(helpers, "immunization"))

    def test_diagnosticreport_alias_exists(self):
        """Test diagnosticreport alias is defined"""
        from oida.protocols.fhir import helpers

        self.assertTrue(hasattr(helpers, "diagnosticreport"))

    def test_documentreference_alias_exists(self):
        """Test documentreference alias is defined"""
        from oida.protocols.fhir import helpers

        self.assertTrue(hasattr(helpers, "documentreference"))


if __name__ == "__main__":
    unittest.main()
