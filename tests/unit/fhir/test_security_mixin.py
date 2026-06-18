#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for FHIR SecurityMixin.

Tests authentication testing, credential brute forcing, and security analysis.
"""

import unittest
from unittest.mock import Mock, patch, MagicMock, mock_open

from oida.protocols.fhir.mixins.security import SecurityMixin


class MockSecurityHost(SecurityMixin):
    """Mock host class that mixes in SecurityMixin for testing."""

    def __init__(self, **arg_overrides):
        self.args = Mock()
        self.logger = Mock()
        self.logger.findings = []
        self.results = {"data": {}}
        self.smart_client = Mock()
        self.host = "https://fhir.example.com/r4"

        defaults = dict(
            patient_id=None,
            confirm=False,
            token=None,
            username=None,
            password=None,
            token_url=None,
            client_id=None,
            client_secret=None,
            scope=None,
            tls_insecure=False,
            brute=False,
            brute_method="basic",
            brute_rate=0,
            stop_on_success=True,
            user_file=None,
            pass_file=None,
            wordlist=None,
            default_creds=False,
        )
        defaults.update(arg_overrides)
        for k, v in defaults.items():
            setattr(self.args, k, v)

    def _get_base_url(self):
        return "https://fhir.example.com/r4"


class TestTestAuthentication(unittest.TestCase):
    """Test _test_authentication() method"""

    @patch("oida.protocols.fhir.mixins.security.patient")
    @patch("oida.protocols.fhir.mixins.security.fhirclient")
    def test_anonymous_access_allowed(self, mock_fhirclient, mock_patient):
        """Test anonymous access detected when patient data returned"""
        host = MockSecurityHost()

        mock_client = MagicMock()
        mock_fhirclient.FHIRClient.return_value = mock_client

        mock_search = Mock()
        mock_search.perform_resources.return_value = [Mock()]
        mock_patient.Patient.where.return_value = mock_search

        host._test_authentication()

        self.assertTrue(host.results["data"]["auth_test"]["anonymous_access"])
        host.logger.security_finding.assert_called()
        findings = host.results["data"].get("security_findings", [])
        anon_findings = [f for f in findings if "Anonymous" in f.get("issue", "")]
        self.assertTrue(len(anon_findings) > 0)

    @patch("oida.protocols.fhir.mixins.security.patient")
    @patch("oida.protocols.fhir.mixins.security.fhirclient")
    def test_anonymous_denied_401(self, mock_fhirclient, mock_patient):
        """Test anonymous access properly denied with 401"""
        host = MockSecurityHost()

        mock_client = MagicMock()
        mock_fhirclient.FHIRClient.return_value = mock_client

        mock_search = Mock()
        mock_search.perform_resources.side_effect = Exception("HTTP 401 Unauthorized")
        mock_patient.Patient.where.return_value = mock_search

        host._test_authentication()
        host.logger.success.assert_called()

    @patch("oida.protocols.fhir.mixins.security.patient")
    @patch("oida.protocols.fhir.mixins.security.fhirclient")
    def test_anonymous_denied_403(self, mock_fhirclient, mock_patient):
        """Test anonymous access properly denied with 403"""
        host = MockSecurityHost()

        mock_client = MagicMock()
        mock_fhirclient.FHIRClient.return_value = mock_client

        mock_search = Mock()
        mock_search.perform_resources.side_effect = Exception("HTTP 403 Forbidden")
        mock_patient.Patient.where.return_value = mock_search

        host._test_authentication()
        host.logger.success.assert_called()

    @patch("oida.protocols.fhir.mixins.security.patient")
    @patch("oida.protocols.fhir.mixins.security.fhirclient")
    def test_invalid_token_accepted(self, mock_fhirclient, mock_patient):
        """Test detection when invalid token is accepted"""
        host = MockSecurityHost()

        mock_client = MagicMock()
        mock_fhirclient.FHIRClient.return_value = mock_client

        # First call (anonymous) - denied, second call (bad token) - accepted
        anon_search = Mock()
        anon_search.perform_resources.side_effect = Exception("401 Unauthorized")

        bad_search = Mock()
        bad_search.perform_resources.return_value = [Mock()]

        call_count = [0]

        def where_side_effect(**kwargs):
            call_count[0] += 1
            if call_count[0] <= 1:
                return anon_search
            return bad_search

        mock_patient.Patient.where.side_effect = where_side_effect

        host._test_authentication()

        self.assertFalse(host.results["data"]["auth_test"]["invalid_token_rejected"])

    @patch("oida.protocols.fhir.mixins.security.patient")
    @patch("oida.protocols.fhir.mixins.security.fhirclient")
    def test_invalid_token_rejected(self, mock_fhirclient, mock_patient):
        """Test invalid token properly rejected"""
        host = MockSecurityHost()

        mock_client = MagicMock()
        mock_fhirclient.FHIRClient.return_value = mock_client

        mock_search = Mock()
        mock_search.perform_resources.side_effect = Exception("401 Unauthorized")
        mock_patient.Patient.where.return_value = mock_search

        host._test_authentication()

        self.assertTrue(host.results["data"]["auth_test"]["invalid_token_rejected"])


class TestTestCrossPatientAccess(unittest.TestCase):
    """Test _test_cross_patient_access() method"""

    def test_no_patient_id_warns(self):
        """Test warning when no patient_id provided"""
        host = MockSecurityHost(patient_id=None)
        host._test_cross_patient_access()
        host.logger.warning.assert_called()

    def test_with_patient_id(self):
        """Test message displayed when patient_id provided"""
        host = MockSecurityHost(patient_id="PT001")
        host._test_cross_patient_access()
        host.logger.display.assert_called()


class TestTestScopeBypass(unittest.TestCase):
    """Test _test_scope_bypass() method"""

    def test_smart_detected(self):
        """Test message when SMART is detected"""
        host = MockSecurityHost()
        host.results["data"]["server_info"] = {
            "security": {
                "security_services": [{"code": "SMART-on-FHIR", "display": "SMART"}],
            }
        }

        host._test_scope_bypass()
        host.logger.display.assert_called()
        host.logger.security_finding.assert_not_called()

    def test_no_smart_security_finding(self):
        """Test security finding when no SMART detected"""
        host = MockSecurityHost()
        host.results["data"]["server_info"] = {"security": {"security_services": []}}

        host._test_scope_bypass()
        host.logger.security_finding.assert_called()


class TestBulkExport(unittest.TestCase):
    """Test _bulk_export() method"""

    def test_no_confirm_flag(self):
        """Test bulk export fails without --confirm flag"""
        host = MockSecurityHost(confirm=False)
        host._bulk_export()
        host.logger.fail.assert_called()

    def test_with_confirm_flag(self):
        """Test bulk export proceeds with --confirm flag"""
        host = MockSecurityHost(confirm=True)
        host._bulk_export()
        host.logger.display.assert_called()
        display_calls = [str(c) for c in host.logger.display.call_args_list]
        endpoint_calls = [c for c in display_calls if "$export" in c]
        self.assertTrue(len(endpoint_calls) > 0)


class TestLoadCredentials(unittest.TestCase):
    """Test _load_credentials() method"""

    def test_from_user_file(self):
        """Test loading usernames from user_file"""
        host = MockSecurityHost(user_file="/tmp/users.txt")

        file_content = "admin\nfhir\napi\n"
        with (
            patch("builtins.open", mock_open(read_data=file_content)),
            patch(
                "oida.protocols.fhir.mixins.security.validate_credential_path",
                return_value="/tmp/users.txt",
            ),
        ):
            usernames, passwords = host._load_credentials()

        self.assertEqual(len(usernames), 3)
        self.assertIn("admin", usernames)

    def test_from_pass_file(self):
        """Test loading passwords from pass_file"""
        host = MockSecurityHost(pass_file="/tmp/passwords.txt")

        file_content = "password1\npassword2\n"
        with (
            patch("builtins.open", mock_open(read_data=file_content)),
            patch(
                "oida.protocols.fhir.mixins.security.validate_credential_path",
                return_value="/tmp/passwords.txt",
            ),
        ):
            usernames, passwords = host._load_credentials()

        self.assertEqual(len(passwords), 2)

    @patch("oida.protocols.fhir.mixins.security.validate_credential_path")
    def test_from_username_password_args(self, mock_validate):
        """Test loading from --username and --password args"""
        host = MockSecurityHost(username="admin", password="secret")

        with patch("oida.utils.default_credentials.parse_credential_input") as mock_parse:
            mock_parse.side_effect = [
                (["admin"], False),
                (["secret"], False),
            ]
            usernames, passwords = host._load_credentials()

        self.assertEqual(usernames, ["admin"])
        self.assertEqual(passwords, ["secret"])

    def test_from_wordlist(self):
        """Test loading from wordlist (user:pass format)"""
        host = MockSecurityHost(wordlist="/tmp/wordlist.txt")

        file_content = "admin:password\nfhir:changeme\n"
        with (
            patch("builtins.open", mock_open(read_data=file_content)),
            patch(
                "oida.protocols.fhir.mixins.security.validate_credential_path",
                return_value="/tmp/wordlist.txt",
            ),
        ):
            usernames, passwords = host._load_credentials()

        self.assertIn("admin", usernames)
        self.assertIn("fhir", usernames)
        self.assertIn("password", passwords)
        self.assertIn("changeme", passwords)

    def test_default_creds_flag(self):
        """Test --default-creds loads built-in credentials"""
        host = MockSecurityHost(default_creds=True)

        usernames, passwords = host._load_credentials()

        self.assertTrue(len(usernames) > 0)
        self.assertTrue(len(passwords) > 0)
        self.assertIn("admin", usernames)
        self.assertIn("password", passwords)

    def test_path_traversal_in_user_file_rejected(self):
        """Test directory traversal in user_file is rejected"""
        host = MockSecurityHost(user_file="/tmp/../etc/passwd")

        with patch(
            "oida.protocols.fhir.mixins.security.validate_credential_path",
            side_effect=ValueError("Path traversal blocked"),
        ):
            usernames, passwords = host._load_credentials()

        host.logger.fail.assert_called()
        self.assertEqual(len(usernames), 0)

    def test_path_traversal_in_pass_file_rejected(self):
        """Test directory traversal in pass_file is rejected"""
        host = MockSecurityHost(pass_file="../../../etc/shadow")

        with patch(
            "oida.protocols.fhir.mixins.security.validate_credential_path",
            side_effect=ValueError("Path traversal blocked"),
        ):
            usernames, passwords = host._load_credentials()

        host.logger.fail.assert_called()


class TestTestOAuth2Credentials(unittest.TestCase):
    """Test _test_oauth2_credentials() method"""

    def test_no_token_url_returns_none(self):
        """Test returns None when no token_url available"""
        host = MockSecurityHost(token_url=None)
        host.results["data"]["server_info"] = {"security": {"oauth_endpoints": {}}}

        result = host._test_oauth2_credentials("admin", "pass")
        self.assertIsNone(result)

    @patch("requests.post")
    def test_successful_auth(self, mock_post):
        """Test successful OAuth2 authentication returns token"""
        host = MockSecurityHost(token_url="https://auth.example.com/token")
        host.results["data"]["server_info"] = {"security": {"oauth_endpoints": {}}}

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"access_token": "valid_token_abc"}
        mock_post.return_value = mock_response

        result = host._test_oauth2_credentials("admin", "password")
        self.assertEqual(result, "valid_token_abc")
        host.logger.security_finding.assert_called()

    @patch("requests.post")
    def test_failed_auth(self, mock_post):
        """Test failed OAuth2 authentication returns None"""
        host = MockSecurityHost(token_url="https://auth.example.com/token")
        host.results["data"]["server_info"] = {"security": {"oauth_endpoints": {}}}

        mock_response = Mock()
        mock_response.status_code = 401
        mock_post.return_value = mock_response

        result = host._test_oauth2_credentials("admin", "wrong")
        self.assertIsNone(result)

    @patch("requests.post")
    def test_exception_returns_none(self, mock_post):
        """Test exception during OAuth2 returns None"""
        host = MockSecurityHost(token_url="https://auth.example.com/token")
        host.results["data"]["server_info"] = {"security": {"oauth_endpoints": {}}}

        mock_post.side_effect = Exception("Connection error")

        result = host._test_oauth2_credentials("admin", "pass")
        self.assertIsNone(result)

    @patch("requests.post")
    def test_token_url_from_oauth_endpoints(self, mock_post):
        """Test token_url discovered from CapabilityStatement"""
        host = MockSecurityHost(token_url=None)
        host.results["data"]["server_info"] = {
            "security": {"oauth_endpoints": {"token": "https://auth.example.com/token"}}
        }

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"access_token": "discovered_token"}
        mock_post.return_value = mock_response

        result = host._test_oauth2_credentials("admin", "pass")
        self.assertEqual(result, "discovered_token")


class TestAnalyzeSecurity(unittest.TestCase):
    """Test _analyze_security() method"""

    def test_no_tls_finding(self):
        """Test finding generated when TLS not enabled"""
        host = MockSecurityHost()
        host.results["data"]["tls_enabled"] = False
        host.results["data"]["server_info"] = {
            "security": {"security_services": [{"code": "OAuth"}], "cors_enabled": False}
        }

        host._analyze_security()

        findings = host.results["data"]["security_findings"]
        tls_findings = [f for f in findings if f.get("category") == "ENCRYPTION"]
        self.assertTrue(len(tls_findings) > 0)

    def test_no_security_services_finding(self):
        """Test finding when no security services configured"""
        host = MockSecurityHost()
        host.results["data"]["tls_enabled"] = True
        host.results["data"]["server_info"] = {
            "security": {"security_services": [], "cors_enabled": False}
        }

        host._analyze_security()

        findings = host.results["data"]["security_findings"]
        auth_findings = [f for f in findings if f.get("category") == "AUTHENTICATION"]
        self.assertTrue(len(auth_findings) > 0)

    def test_cors_finding(self):
        """Test CORS enabled generates finding"""
        host = MockSecurityHost()
        host.results["data"]["tls_enabled"] = True
        host.results["data"]["server_info"] = {
            "security": {
                "security_services": [{"code": "OAuth"}],
                "cors_enabled": True,
            }
        }

        host._analyze_security()

        findings = host.results["data"]["security_findings"]
        cors_findings = [f for f in findings if f.get("category") == "CONFIGURATION"]
        self.assertTrue(len(cors_findings) > 0)
        self.assertIn("CORS", cors_findings[0]["issue"])

    def test_certificate_findings_from_logger(self):
        """Test certificate findings extracted from logger"""
        host = MockSecurityHost()
        host.results["data"]["tls_enabled"] = True
        host.results["data"]["server_info"] = {
            "security": {
                "security_services": [{"code": "OAuth"}],
                "cors_enabled": False,
            }
        }
        host.logger.findings = [
            {"title": "Self-signed cert", "detail": "Certificate is self-signed"}
        ]

        host._analyze_security()

        findings = host.results["data"]["security_findings"]
        cert_findings = [f for f in findings if f.get("category") == "CERTIFICATE"]
        self.assertTrue(len(cert_findings) > 0)
        self.assertEqual(cert_findings[0]["issue"], "Self-signed cert")

    def test_findings_displayed(self):
        """Test findings are displayed to logger"""
        host = MockSecurityHost()
        host.results["data"]["tls_enabled"] = False
        host.results["data"]["server_info"] = {
            "security": {"security_services": [], "cors_enabled": False}
        }

        host._analyze_security()
        display_calls = [str(c) for c in host.logger.display.call_args_list]
        header_calls = [c for c in display_calls if "Security Findings" in c]
        self.assertTrue(len(header_calls) > 0)

    def test_no_findings_no_display(self):
        """Test no display when all checks pass and no pre-existing findings"""
        host = MockSecurityHost()
        host.results["data"]["tls_enabled"] = True
        host.results["data"]["server_info"] = {
            "security": {
                "security_services": [{"code": "OAuth"}],
                "cors_enabled": False,
            }
        }
        host.logger.findings = []

        host._analyze_security()

        findings = host.results["data"]["security_findings"]
        self.assertEqual(len(findings), 0)


class TestBruteForceCredentials(unittest.TestCase):
    """Test _brute_force_credentials() method"""

    @patch("requests.get")
    def test_successful_basic_auth(self, mock_get):
        """Test successful basic auth credential found"""
        host = MockSecurityHost(brute=True, brute_method="basic", brute_rate=0)
        host.results["data"]["server_info"] = {"security": {"oauth_endpoints": {}}}

        mock_response = Mock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        with patch.object(host, "_load_credentials", return_value=(["admin"], ["password"])):
            host._brute_force_credentials()

        self.assertTrue(len(host.results["data"]["brute_force"]["valid"]) > 0)
        host.logger.security_finding.assert_called()

    @patch("requests.get")
    def test_failed_basic_auth(self, mock_get):
        """Test no valid credentials found"""
        host = MockSecurityHost(brute=True, brute_method="basic", brute_rate=0)

        mock_response = Mock()
        mock_response.status_code = 401
        mock_get.return_value = mock_response

        with patch.object(host, "_load_credentials", return_value=(["admin"], ["wrong"])):
            host._brute_force_credentials()

        self.assertEqual(len(host.results["data"]["brute_force"]["valid"]), 0)

    def test_no_credentials_to_test(self):
        """Test fails when no credentials loaded"""
        host = MockSecurityHost(brute=True)

        with patch.object(host, "_load_credentials", return_value=([], [])):
            host._brute_force_credentials()

        host.logger.fail.assert_called()

    @patch("requests.get")
    def test_stop_on_success(self, mock_get):
        """Test brute force stops on first valid credential when flag set"""
        host = MockSecurityHost(
            brute=True, brute_method="basic", brute_rate=0, stop_on_success=True
        )

        mock_response = Mock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        with patch.object(
            host, "_load_credentials", return_value=(["admin", "root"], ["pass1", "pass2"])
        ):
            host._brute_force_credentials()

        # Should find only 1 valid credential (stops after first success)
        self.assertEqual(len(host.results["data"]["brute_force"]["valid"]), 1)

    @patch("requests.get")
    def test_timeout_handling(self, mock_get):
        """Test timeout during brute force is handled"""
        import requests as req

        host = MockSecurityHost(brute=True, brute_method="basic", brute_rate=0)
        mock_get.side_effect = req.exceptions.Timeout("timed out")

        with patch.object(host, "_load_credentials", return_value=(["admin"], ["pass"])):
            host._brute_force_credentials()

        # Should not crash, should report 0 valid
        self.assertEqual(host.results["data"]["brute_force"]["tested"], 1)
        self.assertEqual(len(host.results["data"]["brute_force"]["valid"]), 0)


if __name__ == "__main__":
    unittest.main()
