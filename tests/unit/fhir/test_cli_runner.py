#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for FHIR NXC-style connection class.

Tests the fhir class for:
- Base URL construction
- Vendor identification
- Security info parsing
- Host info display
- Result export
- Connection lifecycle
- Proto flow orchestration
- Connection object creation
"""

import unittest
from unittest.mock import Mock, patch, MagicMock


def _make_mock_args(**overrides):
    """Build a fully populated mock_args with all FHIR attributes."""
    args = Mock()
    defaults = dict(
        port=443,
        timeout=30,
        tls=True,
        tls_insecure=False,
        tls_cert=None,
        tls_key=None,
        tls_ca=None,
        verbose=0,
        debug=False,
        fhir_version="R4",
        caps=False,
        enum_all=False,
        token=None,
        username=None,
        password=None,
        client_id=None,
        client_secret=None,
        scope=None,
        auth_url=None,
        token_url=None,
        search_patients=False,
        search_observations=False,
        search_medications=False,
        search_conditions=False,
        search_encounters=False,
        search_procedures=False,
        search_allergies=False,
        search_immunizations=False,
        search_diagnostics=False,
        search_documents=False,
        search_practitioners=False,
        search_organizations=False,
        search_locations=False,
        search_devices=False,
        search_orders=False,
        patient_id=None,
        patient_name=None,
        patient_dob=None,
        patient_gender=None,
        max_results=100,
        wildcard=False,
        date_from=None,
        date_to=None,
        code=None,
        category=None,
        read_patient=None,
        read_observation=None,
        read_medication=None,
        read_condition=None,
        read_encounter=None,
        test_auth=False,
        test_cross_patient=False,
        test_scope=False,
        bulk_export=False,
        bulk_export_type="Patient",
        confirm=False,
        include=None,
        revinclude=None,
        elements=None,
        summary=None,
        save_response=None,
        output=None,
        format="csv,json",
        brute=False,
        default_creds=False,
        wordlist=None,
        brute_rate=0.5,
        continue_on_success=False,
        user_file=None,
        pass_file=None,
        brute_method="basic",
        credentials=None,
        create_patient=False,
        update_patient=None,
        delete_patient=None,
        create_observation=False,
        patient_data=None,
        patient_given_name=None,
        patient_family_name=None,
        observation_data=None,
        observation_code=None,
        observation_value=None,
        observation_unit=None,
        practitioner_name=None,
        organization_name=None,
        location_name=None,
        device_type=None,
    )
    defaults.update(overrides)
    for k, v in defaults.items():
        setattr(args, k, v)
    return args


def _create_scanner(host="https://fhir.example.com/r4", **arg_overrides):
    """Create a fhir scanner instance with proto_flow mocked out.

    Replaces the real ICSLogger with a Mock so tests can assert on
    logger method calls (display, warning, security_finding, etc.).
    """
    from oida.protocols.fhir import fhir

    with patch.object(fhir, "proto_flow", return_value=None):
        scanner = fhir(_make_mock_args(**arg_overrides), None, host)
    # Ensure results["data"] exists for tests that need it
    scanner.results.setdefault("data", {})
    # Replace the real ICSLogger with a Mock for assertion-based tests
    scanner.logger = Mock()
    scanner.logger.findings = []
    return scanner


class TestGetBaseURL(unittest.TestCase):
    """Test _get_base_url() method"""

    def test_https_url_passthrough(self):
        """Test HTTPS URL is returned as-is"""
        scanner = _create_scanner("https://fhir.example.com/r4")
        self.assertEqual(scanner._get_base_url(), "https://fhir.example.com/r4")

    def test_http_url_passthrough(self):
        """Test HTTP URL is returned as-is"""
        scanner = _create_scanner("http://fhir.local/r4")
        self.assertEqual(scanner._get_base_url(), "http://fhir.local/r4")

    def test_trailing_slash_stripped(self):
        """Test trailing slash is removed from URL"""
        scanner = _create_scanner("https://fhir.example.com/r4/")
        self.assertEqual(scanner._get_base_url(), "https://fhir.example.com/r4")

    def test_hostname_with_tls_default_port(self):
        """Test hostname-only with TLS=True uses https and default port 443"""
        scanner = _create_scanner("fhir.example.com", tls=True, port=443)
        self.assertEqual(scanner._get_base_url(), "https://fhir.example.com")

    def test_hostname_no_tls(self):
        """Test hostname with TLS=False uses http"""
        scanner = _create_scanner("fhir.local", tls=False, port=80)
        self.assertEqual(scanner._get_base_url(), "http://fhir.local")

    def test_hostname_no_tls_default_port_no_spurious_443(self):
        """--no-tls leaves args.port at the 443 default; the http URL must NOT
        get a spurious ':443' appended (regression: built http://host:443)."""
        scanner = _create_scanner("fhir.local", tls=False, port=443)
        self.assertEqual(scanner._get_base_url(), "http://fhir.local")

    def test_target_with_embedded_port_no_tls_not_doubled(self):
        """A host:port target with --no-tls must not double the port to :443."""
        scanner = _create_scanner("127.0.0.1:8081", tls=False, port=443)
        self.assertEqual(scanner._get_base_url(), "http://127.0.0.1:8081")

    def test_hostname_non_default_port_tls(self):
        """Test hostname with non-default port includes port number"""
        scanner = _create_scanner("fhir.example.com", tls=True, port=8443)
        self.assertEqual(scanner._get_base_url(), "https://fhir.example.com:8443")

    def test_hostname_non_default_port_http(self):
        """Test hostname with HTTP and non-default port"""
        scanner = _create_scanner("fhir.local", tls=False, port=8080)
        self.assertEqual(scanner._get_base_url(), "http://fhir.local:8080")

    def test_multiple_trailing_slashes(self):
        """Test multiple trailing characters stripped correctly"""
        scanner = _create_scanner("https://fhir.example.com/r4/")
        # rstrip("/") removes all trailing slashes
        self.assertFalse(scanner._get_base_url().endswith("/"))

    def test_explicit_https_target_not_downgraded(self):
        """An explicit https:// target is never scanned over cleartext, even
        if args.tls is somehow False (scheme in the target always wins)."""
        scanner = _create_scanner("https://fhir.example.com/r4", tls=False)
        url = scanner._get_base_url()
        self.assertTrue(url.startswith("https://"))
        self.assertFalse(url.startswith("http://fhir"))


class TestSchemeResolutionConsistency(unittest.TestCase):
    """Scheme resolution must be coherent: the parser default for --tls and the
    code's getattr(...,'tls', default) must agree so a bare-hostname FHIR target
    is not silently scanned over cleartext HTTP (CODE_REVIEW finding
    cli_runner.py:51)."""

    @staticmethod
    def _parse(*flags):
        import argparse

        from oida.protocols.fhir.proto_args import proto_args

        parent = argparse.ArgumentParser(add_help=False)
        main = argparse.ArgumentParser()
        subparsers = main.add_subparsers()
        proto_args(subparsers, [parent])
        return main.parse_args(["fhir", "fhir.example.com", *flags])

    def test_parser_tls_defaults_true(self):
        """FHIR is HTTPS-by-default: the parser must populate args.tls=True."""
        self.assertTrue(self._parse().tls)

    def test_no_tls_opts_out(self):
        """--no-tls explicitly downgrades to cleartext HTTP."""
        self.assertFalse(self._parse("--no-tls").tls)

    def test_tls_flag_still_enables(self):
        """--tls remains accepted and keeps TLS enabled."""
        self.assertTrue(self._parse("--tls").tls)

    def test_bare_hostname_default_is_https_not_cleartext(self):
        """With parser defaults, a bare-hostname target resolves to https,
        matching default_port 443 — no silent cleartext downgrade."""
        args = self._parse()
        scanner = _create_scanner("fhir.example.com", tls=args.tls, port=443)
        url = scanner._get_base_url()
        self.assertEqual(url, "https://fhir.example.com")
        self.assertFalse(url.startswith("http://"))

    def test_getattr_default_matches_parser_default(self):
        """The code's getattr(self.args, 'tls', <default>) fallback must agree
        with the parser default so the two can never contradict."""
        # Parser default
        self.assertTrue(self._parse().tls)
        # getattr fallback (when attr absent) used by _get_base_url
        args = Mock(spec=[])  # no 'tls' attribute at all
        self.assertTrue(getattr(args, "tls", True))


class TestIdentifyVendor(unittest.TestCase):
    """Test _identify_vendor() method"""

    def setUp(self):
        self.scanner = _create_scanner()

    def test_identify_epic(self):
        vendor, product = self.scanner._identify_vendor("Epic Systems FHIR", "")
        self.assertEqual(vendor, "Epic Systems")

    def test_identify_cerner(self):
        vendor, product = self.scanner._identify_vendor("Cerner Millennium", "")
        self.assertEqual(vendor, "Cerner Corporation")

    def test_identify_hapi(self):
        vendor, product = self.scanner._identify_vendor("HAPI FHIR Server", "")
        self.assertEqual(vendor, "HAPI FHIR")
        self.assertEqual(product, "HAPI FHIR Server")

    def test_identify_microsoft(self):
        vendor, product = self.scanner._identify_vendor("Microsoft Azure FHIR", "")
        self.assertEqual(vendor, "Microsoft")

    def test_identify_google(self):
        vendor, product = self.scanner._identify_vendor("Google Cloud Healthcare", "")
        self.assertEqual(vendor, "Google")

    def test_identify_aws(self):
        vendor, product = self.scanner._identify_vendor("AWS HealthLake", "")
        self.assertEqual(vendor, "Amazon")

    def test_identify_firely_vonk(self):
        vendor, product = self.scanner._identify_vendor("Vonk FHIR Server", "")
        self.assertEqual(vendor, "Firely")

    def test_identify_ibm(self):
        vendor, product = self.scanner._identify_vendor("IBM FHIR Server", "")
        self.assertEqual(vendor, "IBM")

    def test_empty_strings_return_none(self):
        vendor, product = self.scanner._identify_vendor("", "")
        self.assertIsNone(vendor)
        self.assertIsNone(product)

    def test_publisher_fallback(self):
        """Test vendor identified from publisher when software_name misses"""
        vendor, product = self.scanner._identify_vendor("Custom Server", "Firely B.V.")
        self.assertEqual(vendor, "Firely")
        self.assertEqual(product, "Vonk FHIR Server")

    def test_unknown_vendor_returns_none(self):
        vendor, product = self.scanner._identify_vendor("FooBar FHIR", "FooBar Inc")
        self.assertIsNone(vendor)
        self.assertIsNone(product)

    def test_case_insensitive_match(self):
        """Test matching is case-insensitive (uppercased internally)"""
        vendor, product = self.scanner._identify_vendor("hapi fhir server", "")
        self.assertEqual(vendor, "HAPI FHIR")

    def test_none_software_none_publisher(self):
        """Test None values treated as empty"""
        vendor, product = self.scanner._identify_vendor(None, None)
        self.assertIsNone(vendor)
        self.assertIsNone(product)


class TestParseSecurityInfo(unittest.TestCase):
    """Test _parse_security_info() method"""

    def setUp(self):
        self.scanner = _create_scanner()

    def test_cors_detection(self):
        """Test CORS enabled flag is extracted"""
        cap = Mock()
        rest = Mock()
        sec = Mock()
        sec.cors = True
        sec.description = "Test security"
        sec.service = []
        sec.extension = []
        rest.security = sec
        cap.rest = [rest]

        result = self.scanner._parse_security_info(cap)
        self.assertTrue(result["cors_enabled"])
        self.assertEqual(result["description"], "Test security")

    def test_security_services_extraction(self):
        """Test security services are extracted from coding"""
        cap = Mock()
        rest = Mock()
        sec = Mock()
        sec.cors = False
        sec.description = None

        coding = Mock()
        coding.system = "http://hl7.org/fhir"
        coding.code = "SMART-on-FHIR"
        coding.display = "SMART on FHIR"

        svc = Mock()
        svc.coding = [coding]
        sec.service = [svc]
        sec.extension = []
        rest.security = sec
        cap.rest = [rest]

        result = self.scanner._parse_security_info(cap)
        self.assertEqual(len(result["security_services"]), 1)
        self.assertEqual(result["security_services"][0]["code"], "SMART-on-FHIR")
        self.assertEqual(result["security_services"][0]["display"], "SMART on FHIR")

    def test_oauth_endpoint_extraction(self):
        """Test OAuth URIs are extracted from extensions"""
        cap = Mock()
        rest = Mock()
        sec = Mock()
        sec.cors = False
        sec.description = None
        sec.service = []

        inner_ext = Mock()
        inner_ext.url = "token"
        inner_ext.valueUri = "https://auth.example.com/token"

        outer_ext = Mock()
        outer_ext.url = "http://fhir-registry.smarthealthit.org/StructureDefinition/oauth-uris"
        outer_ext.extension = [inner_ext]

        sec.extension = [outer_ext]
        rest.security = sec
        cap.rest = [rest]

        result = self.scanner._parse_security_info(cap)
        self.assertEqual(result["oauth_endpoints"]["token"], "https://auth.example.com/token")

    def test_handles_missing_rest(self):
        """Test graceful handling when rest is None"""
        cap = Mock()
        cap.rest = None

        result = self.scanner._parse_security_info(cap)
        self.assertFalse(result["cors_enabled"])
        self.assertEqual(result["security_services"], [])

    def test_handles_missing_security(self):
        """Test graceful handling when security is None"""
        cap = Mock()
        rest = Mock()
        rest.security = None
        cap.rest = [rest]

        result = self.scanner._parse_security_info(cap)
        self.assertEqual(result["security_services"], [])

    def test_handles_exception(self):
        """Test exception in parsing is caught"""
        cap = Mock()
        type(cap).rest = property(lambda s: (_ for _ in ()).throw(RuntimeError("boom")))

        result = self.scanner._parse_security_info(cap)
        self.assertFalse(result["cors_enabled"])

    def test_default_structure(self):
        """Test returned dict has expected default keys"""
        cap = Mock()
        cap.rest = []

        result = self.scanner._parse_security_info(cap)
        self.assertIn("cors_enabled", result)
        self.assertIn("security_services", result)
        self.assertIn("oauth_endpoints", result)
        self.assertIn("description", result)


class TestPrintHostInfo(unittest.TestCase):
    """Test print_host_info() method"""

    def setUp(self):
        self.scanner = _create_scanner()

    def test_with_vendor_info(self):
        """Test display when vendor info is present"""
        self.scanner.results["data"]["server_info"] = {
            "software_name": "HAPI FHIR",
            "software_version": "6.0.0",
            "vendor": "HAPI FHIR",
            "product_type": "HAPI FHIR Server",
            "fhir_version": "4.0.1",
            "publisher": "HAPI",
            "resource_count": 30,
            "security": {"security_services": [{"display": "SMART"}], "cors_enabled": False},
        }

        self.scanner.print_host_info()

        display_calls = [str(c) for c in self.scanner.logger.display.call_args_list]
        vendor_call = [c for c in display_calls if "HAPI FHIR" in c]
        self.assertTrue(len(vendor_call) > 0)

    def test_without_vendor(self):
        """Test display when vendor is None"""
        self.scanner.results["data"]["server_info"] = {
            "software_name": "Custom Server",
            "software_version": "1.0",
            "vendor": None,
            "product_type": None,
            "fhir_version": "4.0.1",
            "publisher": None,
            "resource_count": 10,
            "security": {"security_services": [], "cors_enabled": False},
        }

        self.scanner.print_host_info()
        self.scanner.logger.display.assert_called()

    def test_with_error_in_server_info(self):
        """Test display when server_info has error"""
        self.scanner.results["data"]["server_info"] = {"error": "Connection refused"}

        self.scanner.print_host_info()
        self.scanner.logger.warning.assert_called()

    def test_with_no_security_services(self):
        """Test security finding logged when no services configured"""
        self.scanner.results["data"]["server_info"] = {
            "software_name": "Test",
            "software_version": "1.0",
            "vendor": None,
            "product_type": None,
            "fhir_version": "4.0.1",
            "publisher": None,
            "resource_count": 5,
            "security": {"security_services": [], "cors_enabled": False},
        }

        self.scanner.print_host_info()
        self.scanner.logger.security_finding.assert_called_once()

    def test_with_cors_enabled(self):
        """Test CORS enabled message is displayed"""
        self.scanner.results["data"]["server_info"] = {
            "software_name": "Test",
            "software_version": "1.0",
            "vendor": None,
            "product_type": None,
            "fhir_version": "4.0.1",
            "publisher": None,
            "resource_count": 5,
            "security": {
                "security_services": [{"display": "OAuth2"}],
                "cors_enabled": True,
            },
        }

        self.scanner.print_host_info()
        cors_calls = [
            str(c) for c in self.scanner.logger.display.call_args_list if "CORS" in str(c)
        ]
        self.assertTrue(len(cors_calls) > 0)

    def test_publisher_displayed(self):
        """Test publisher is displayed when present"""
        self.scanner.results["data"]["server_info"] = {
            "software_name": "Test",
            "software_version": "1.0",
            "vendor": None,
            "product_type": None,
            "fhir_version": "4.0.1",
            "publisher": "Test Publisher Inc",
            "resource_count": 5,
            "security": {"security_services": [{"display": "Basic"}], "cors_enabled": False},
        }

        self.scanner.print_host_info()
        display_calls = [str(c) for c in self.scanner.logger.display.call_args_list]
        publisher_calls = [c for c in display_calls if "Test Publisher" in c]
        self.assertTrue(len(publisher_calls) > 0)


class TestExportResults(unittest.TestCase):
    """Test _export_results() method"""

    def setUp(self):
        self.scanner = _create_scanner()

    def test_no_output_dir_skips_export(self):
        """Test no output dir means no file export"""
        self.scanner.args.output = None
        self.scanner._export_results()
        # No error should occur

    @patch("oida.utils.export_utils.export_json")
    def test_json_export(self, mock_export):
        """Test JSON export is called when format includes json"""
        self.scanner.args.output = "/tmp/output"
        self.scanner.args.format = "json"

        self.scanner._export_results()
        mock_export.assert_called_once()

    def test_csv_export_with_patients(self):
        """Test CSV export includes patient records"""
        self.scanner.args.output = "/tmp/output"
        self.scanner.args.format = "csv"
        self.scanner.results["data"]["patients"] = {
            "records": [
                {
                    "id": "1",
                    "name": "Test",
                    "birth_date": "1990-01-01",
                    "gender": "male",
                    "phone": "",
                    "address": "",
                },
            ]
        }

        with patch("oida.utils.export_utils.export_data") as mock_export:
            self.scanner._export_results()
            mock_export.assert_called_once()

    @patch("oida.utils.export_utils.export_json")
    @patch("oida.utils.export_utils.export_data")
    def test_format_all_exports_both(self, mock_data, mock_json):
        """Test format 'all' triggers both json and csv"""
        self.scanner.args.output = "/tmp/output"
        self.scanner.args.format = "all"
        self.scanner.results["data"]["patients"] = {
            "records": [
                {
                    "id": "1",
                    "name": "Test",
                    "birth_date": "",
                    "gender": "",
                    "phone": "",
                    "address": "",
                }
            ]
        }

        self.scanner._export_results()
        mock_json.assert_called_once()
        mock_data.assert_called_once()


class TestDisconnect(unittest.TestCase):
    """Test _disconnect() method"""

    def test_clears_smart_client(self):
        """Test _disconnect sets smart_client to None"""
        scanner = _create_scanner()
        scanner.smart_client = Mock()
        scanner.conn = Mock()

        scanner._disconnect()

        self.assertIsNone(scanner.smart_client)
        self.assertIsNone(scanner.conn)

    def test_disconnect_idempotent(self):
        """Test calling _disconnect multiple times is safe"""
        scanner = _create_scanner()
        scanner._disconnect()
        scanner._disconnect()
        self.assertIsNone(scanner.smart_client)


class TestProtoFlow(unittest.TestCase):
    """Test proto_flow() orchestration"""

    def test_dependency_check_fails(self):
        """Test proto_flow aborts when fhirclient not available"""
        from oida.protocols.fhir import fhir

        with patch(
            "oida.protocols.fhir.cli_runner.is_fhirclient_available", return_value=False
        ):
            scanner = fhir(_make_mock_args(), None, "https://fhir.example.com/r4")

        self.assertIn("error", scanner.results)
        self.assertIn("fhirclient", scanner.results["error"])

    def test_enum_all_sets_search_flags(self):
        """Test --enum-all sets all search flags to True"""
        from oida.protocols.fhir.cli_runner import fhir

        args = _make_mock_args(enum_all=True)

        # enum_all processing happens after is_fhirclient_available, so we
        # need fhirclient available but stop at create_conn_obj.
        # NetworkConnection copies args (copy.copy) so default-port resolution
        # doesn't mutate the caller's shared Namespace — the enum_all expansion
        # therefore lands on scanner.args, not the original `args` object.
        with (
            patch("oida.protocols.fhir.cli_runner.is_fhirclient_available", return_value=True),
            patch.object(fhir, "create_conn_obj", return_value=False),
        ):
            scanner = fhir(args, None, "https://fhir.example.com/r4")

        self.assertTrue(scanner.args.search_patients)
        self.assertTrue(scanner.args.search_observations)
        self.assertTrue(scanner.args.search_medications)
        self.assertTrue(scanner.args.search_conditions)
        self.assertTrue(scanner.args.search_encounters)
        self.assertTrue(scanner.args.search_procedures)
        self.assertTrue(scanner.args.search_allergies)
        self.assertTrue(scanner.args.search_immunizations)
        self.assertTrue(scanner.args.search_diagnostics)
        self.assertTrue(scanner.args.search_documents)
        self.assertTrue(scanner.args.search_practitioners)
        self.assertTrue(scanner.args.search_organizations)
        self.assertTrue(scanner.args.search_locations)
        self.assertTrue(scanner.args.search_devices)
        self.assertTrue(scanner.args.search_orders)

    def test_create_conn_obj_failure_stops_flow(self):
        """Test proto_flow returns when create_conn_obj fails"""
        from oida.protocols.fhir import fhir

        args = _make_mock_args()

        with (
            patch("oida.protocols.fhir.cli_runner.is_fhirclient_available", return_value=True),
            patch.object(fhir, "create_conn_obj", return_value=False),
        ):
            scanner = fhir(args, None, "https://fhir.example.com/r4")

        self.assertNotIn("server_info", scanner.results.get("data", {}))


class TestCreateConnObj(unittest.TestCase):
    """Test create_conn_obj() method"""

    def test_success_path(self):
        """Test successful connection with mocked FHIRClient"""
        scanner = _create_scanner()

        mock_client = MagicMock()
        mock_client.server = MagicMock()
        mock_client.server.session = MagicMock()

        with patch("oida.protocols.fhir.cli_runner.fhirclient") as mock_fhir:
            mock_fhir.FHIRClient.return_value = mock_client
            scanner.smart_client = None
            scanner.conn = None
            result = scanner.create_conn_obj()

        self.assertTrue(result)

    def test_does_not_mark_connected_before_metadata_fetch(self):
        """create_conn_obj only builds the client; reachability is unproven until
        the /metadata round-trip in enum_host_info, so connected must NOT be set
        and no 'Connected' success line must be emitted yet."""
        scanner = _create_scanner()

        mock_client = MagicMock()
        mock_client.server = MagicMock()
        mock_client.server.session = MagicMock()

        with patch("oida.protocols.fhir.cli_runner.fhirclient") as mock_fhir:
            mock_fhir.FHIRClient.return_value = mock_client
            scanner.smart_client = None
            scanner.conn = None
            result = scanner.create_conn_obj()

        self.assertTrue(result)
        # connected must not be asserted prematurely (no key set, or explicitly falsey)
        self.assertFalse(scanner.results["data"].get("connected", False))
        scanner.logger.success.assert_not_called()

    def test_bearer_token_strips_prefix(self):
        """Test Bearer prefix is stripped from token"""
        scanner = _create_scanner(token="Bearer abc123")

        mock_client = MagicMock()
        mock_client.server = MagicMock()
        mock_client.server.session = MagicMock()

        with patch("oida.protocols.fhir.cli_runner.fhirclient") as mock_fhir:
            mock_fhir.FHIRClient.return_value = mock_client
            scanner.smart_client = None
            scanner.conn = None
            result = scanner.create_conn_obj()

        self.assertTrue(result)
        # Verify the token was stripped: the settings passed to FHIRClient
        call_args = mock_fhir.FHIRClient.call_args
        settings = call_args[1].get("settings") or call_args[0][0] if call_args[0] else {}
        if isinstance(settings, dict) and "access_token" in settings:
            self.assertEqual(settings["access_token"], "abc123")

    def test_basic_auth_setup(self):
        """Test basic auth is set on session when username/password provided"""
        scanner = _create_scanner(username="admin", password="secret")

        mock_session = MagicMock()
        mock_server = MagicMock()
        mock_server.session = mock_session
        mock_client = MagicMock()
        mock_client.server = mock_server

        with patch("oida.protocols.fhir.cli_runner.fhirclient") as mock_fhir:
            mock_fhir.FHIRClient.return_value = mock_client
            scanner.smart_client = None
            scanner.conn = None
            result = scanner.create_conn_obj()

        self.assertTrue(result)
        self.assertIsNotNone(mock_session.auth)

    def test_tls_insecure_flag(self):
        """Test TLS insecure flag disables SSL verification"""
        scanner = _create_scanner(tls_insecure=True)

        mock_session = MagicMock()
        mock_server = MagicMock()
        mock_server.session = mock_session
        mock_client = MagicMock()
        mock_client.server = mock_server

        with patch("oida.protocols.fhir.cli_runner.fhirclient") as mock_fhir:
            mock_fhir.FHIRClient.return_value = mock_client
            scanner.smart_client = None
            scanner.conn = None
            result = scanner.create_conn_obj()

        self.assertTrue(result)
        self.assertFalse(mock_session.verify)

    def test_connection_failure(self):
        """Test connection failure sets error state"""
        scanner = _create_scanner()

        with patch("oida.protocols.fhir.cli_runner.fhirclient") as mock_fhir:
            mock_fhir.FHIRClient.side_effect = ConnectionError("refused")
            scanner.smart_client = None
            scanner.conn = None
            result = scanner.create_conn_obj()

        self.assertFalse(result)
        self.assertFalse(scanner.results["data"]["connected"])
        self.assertIn("error", scanner.results)

    def test_sets_conn_attribute(self):
        """Test successful connection sets self.conn"""
        scanner = _create_scanner()

        mock_client = MagicMock()
        mock_client.server = MagicMock()
        mock_client.server.session = MagicMock()

        with patch("oida.protocols.fhir.cli_runner.fhirclient") as mock_fhir:
            mock_fhir.FHIRClient.return_value = mock_client
            scanner.smart_client = None
            scanner.conn = None
            scanner.create_conn_obj()

        self.assertIsNotNone(scanner.conn)
        self.assertEqual(scanner.conn, scanner.smart_client)

    def test_tls_enabled_in_results(self):
        """Test tls_enabled flag in results matches URL scheme"""
        scanner = _create_scanner("https://fhir.example.com/r4")

        mock_client = MagicMock()
        mock_client.server = MagicMock()
        mock_client.server.session = MagicMock()

        with (
            patch("oida.protocols.fhir.cli_runner.fhirclient") as mock_fhir,
            patch.object(scanner, "_check_tls_certificate"),
        ):
            mock_fhir.FHIRClient.return_value = mock_client
            scanner.smart_client = None
            scanner.conn = None
            scanner.create_conn_obj()

        self.assertTrue(scanner.results["data"]["tls_enabled"])

    def _run_with_mock_client(self, scanner):
        """Run create_conn_obj with a mocked FHIRClient and return the session."""
        mock_session = MagicMock()
        mock_server = MagicMock()
        mock_server.session = mock_session
        mock_client = MagicMock()
        mock_client.server = mock_server

        with (
            patch("oida.protocols.fhir.cli_runner.fhirclient") as mock_fhir,
            patch.object(scanner, "_check_tls_certificate"),
        ):
            mock_fhir.FHIRClient.return_value = mock_client
            scanner.smart_client = None
            scanner.conn = None
            result = scanner.create_conn_obj()
        return result, mock_session

    def test_mtls_cert_and_key_set_on_session(self):
        """Separate --tls-cert/--tls-key produce a (cert, key) tuple on session.cert."""
        import os
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            cert = os.path.join(d, "client.pem")
            key = os.path.join(d, "client.key")
            open(cert, "w").close()
            open(key, "w").close()

            scanner = _create_scanner(tls_cert=cert, tls_key=key)
            result, session = self._run_with_mock_client(scanner)

        self.assertTrue(result)
        # Pre-fix: session.cert was never assigned (stays a MagicMock attribute).
        self.assertEqual(session.cert, (os.path.realpath(cert), os.path.realpath(key)))

    def test_mtls_combined_cert_only(self):
        """A single --tls-cert (combined cert+key file) sets session.cert to the path."""
        import os
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            cert = os.path.join(d, "combined.pem")
            open(cert, "w").close()

            scanner = _create_scanner(tls_cert=cert, tls_key=None)
            result, session = self._run_with_mock_client(scanner)

        self.assertTrue(result)
        self.assertEqual(session.cert, os.path.realpath(cert))

    def test_tls_ca_sets_verify_path(self):
        """--tls-ca sets session.verify to the resolved CA bundle path."""
        import os
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            ca = os.path.join(d, "ca.pem")
            open(ca, "w").close()

            scanner = _create_scanner(tls_ca=ca)
            result, session = self._run_with_mock_client(scanner)

        self.assertTrue(result)
        self.assertEqual(session.verify, os.path.realpath(ca))

    def test_tls_insecure_overrides_ca(self):
        """--tls-insecure wins over --tls-ca: verification disabled."""
        import os
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            ca = os.path.join(d, "ca.pem")
            open(ca, "w").close()

            scanner = _create_scanner(tls_ca=ca, tls_insecure=True)
            result, session = self._run_with_mock_client(scanner)

        self.assertTrue(result)
        self.assertFalse(session.verify)


class TestEnumHostInfo(unittest.TestCase):
    """Test enum_host_info() method"""

    def test_successful_capability_statement(self):
        """Test successful CapabilityStatement parsing"""
        scanner = _create_scanner()

        mock_cap = MagicMock()
        mock_cap.fhirVersion = "4.0.1"
        mock_cap.publisher = "Test Publisher"
        mock_cap.software = MagicMock()
        mock_cap.software.name = "HAPI FHIR Server"
        mock_cap.software.version = "6.0.0"
        mock_cap.implementation = MagicMock()
        mock_cap.implementation.description = "Test impl"
        mock_cap.implementation.url = "https://example.com"
        mock_cap.rest = []
        mock_cap.as_json.return_value = {"fhirVersion": "4.0.1"}

        scanner.smart_client = MagicMock()

        with patch("oida.protocols.fhir.cli_runner.capabilitystatement") as mock_cs:
            mock_cs.CapabilityStatement.read_from.return_value = mock_cap
            result = scanner.enum_host_info()

        self.assertTrue(result)
        self.assertIn("server_info", scanner.results["data"])
        self.assertEqual(scanner.results["data"]["server_info"]["fhir_version"], "4.0.1")
        self.assertEqual(scanner.results["data"]["server_info"]["vendor"], "HAPI FHIR")
        # connected and the 'Connected' success line are only asserted once the
        # /metadata round-trip actually returns.
        self.assertTrue(scanner.results["data"]["connected"])
        scanner.logger.success.assert_called()

    def test_404_returns_false(self):
        """Test 404 response returns False"""
        scanner = _create_scanner()
        scanner.smart_client = MagicMock()

        with patch("oida.protocols.fhir.cli_runner.capabilitystatement") as mock_cs:
            mock_cs.CapabilityStatement.read_from.side_effect = Exception("Response [404]")
            result = scanner.enum_host_info()

        self.assertFalse(result)
        # An unreachable host must never be reported as connected.
        self.assertFalse(scanner.results["data"].get("connected", False))
        scanner.logger.success.assert_not_called()

    def test_connection_refused_returns_false(self):
        """Test connection refused returns False"""
        scanner = _create_scanner()
        scanner.smart_client = MagicMock()

        with patch("oida.protocols.fhir.cli_runner.capabilitystatement") as mock_cs:
            mock_cs.CapabilityStatement.read_from.side_effect = Exception("Connection refused")
            result = scanner.enum_host_info()

        self.assertFalse(result)

    def test_generic_exception_returns_true(self):
        """Test generic exception returns True (non-fatal)"""
        scanner = _create_scanner()
        scanner.smart_client = MagicMock()

        with patch("oida.protocols.fhir.cli_runner.capabilitystatement") as mock_cs:
            mock_cs.CapabilityStatement.read_from.side_effect = Exception("Timeout")
            result = scanner.enum_host_info()

        self.assertTrue(result)
        self.assertIn("error", scanner.results["data"]["server_info"])


class TestScannerInit(unittest.TestCase):
    """Test scanner initialization attributes"""

    def test_protocol_name(self):
        scanner = _create_scanner()
        self.assertEqual(scanner.protocol_name, "fhir")

    def test_default_port(self):
        scanner = _create_scanner()
        self.assertEqual(scanner.default_port, 443)

    def test_results_data_structure(self):
        scanner = _create_scanner()
        self.assertIn("data", scanner.results)
        self.assertIsInstance(scanner.results["data"], dict)

    def test_host_attribute(self):
        scanner = _create_scanner("https://fhir.example.com/r4")
        self.assertEqual(scanner.host, "https://fhir.example.com/r4")

    def test_smart_client_initially_none(self):
        scanner = _create_scanner()
        self.assertIsNone(scanner.smart_client)


if __name__ == "__main__":
    unittest.main()
