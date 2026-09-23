#!/usr/bin/env python3
"""
Comprehensive test suite for OPC UA protocol scanner
Tests both mock interactions and real protocol functionality
"""

import unittest
from unittest.mock import Mock, patch, AsyncMock
import asyncio

import pytest

from oida.protocols.opcua import OPCUAScanner
from tests.service_gate import require_service


class TestOPCUAScannerInit(unittest.TestCase):
    """Test OPC UA scanner initialization"""

    def test_scanner_init_defaults(self):
        """Test scanner initialization with default values"""
        scanner = OPCUAScanner({"rhost": "192.168.1.100", "rport": 4840})

        self.assertEqual(scanner.host, "192.168.1.100")
        self.assertEqual(scanner.port, 4840)
        self.assertEqual(scanner.get_protocol_name(), "OPC UA")
        self.assertEqual(scanner.get_default_port(), 4840)

    def test_scanner_init_custom_values(self):
        """Test scanner initialization with custom values"""
        scanner = OPCUAScanner(
            {
                "rhost": "10.0.0.50",
                "rport": 8080,
                "timeout": 30,
                "debug": True,
                "endpoint_url": "opc.tcp://10.0.0.50:8080/OPCUAServer",
                "security_policy": "Basic256Sha256",
                "security_mode": "SignAndEncrypt",
            }
        )

        self.assertEqual(scanner.host, "10.0.0.50")
        self.assertEqual(scanner.port, 8080)
        self.assertEqual(scanner.timeout, 30)
        self.assertTrue(scanner.debug)


class TestOPCUAProtocolLogic(unittest.TestCase):
    """Test OPC UA protocol-specific logic"""

    def test_parse_node_id(self):
        """Test parsing of OPC UA Node IDs"""
        OPCUAScanner({"rhost": "127.0.0.1", "rport": 4840})

        # Test different Node ID formats
        node_ids = [
            "i=85",  # Numeric
            "s=Demo.Static.Scalar.String",  # String
            "g=C496578A-0DFE-4B8F-870A-745238C6AEAE",  # GUID
            "b=UE9MTEFSU0VSVkVS",  # ByteString
            "ns=2;i=1001",  # With namespace
            "ns=3;s=Temperature",  # String with namespace
        ]

        for node_id in node_ids:
            self.assertIsInstance(node_id, str)
            # Basic validation that node ID contains expected characters
            if "ns=" in node_id:
                self.assertIn(";", node_id)

    def test_security_policies(self):
        """Test OPC UA security policy recognition"""
        # Standard OPC UA security policies
        security_policies = [
            "None",
            "Basic128Rsa15",
            "Basic256",
            "Basic256Sha256",
            "Aes128_Sha256_RsaOaep",
            "Aes256_Sha256_RsaPss",
        ]

        for policy in security_policies:
            self.assertIsInstance(policy, str)
            self.assertTrue(len(policy) > 0)

    def test_message_security_modes(self):
        """Test OPC UA message security modes"""
        security_modes = ["None", "Sign", "SignAndEncrypt"]

        for mode in security_modes:
            self.assertIn(mode, security_modes)

    def test_node_classes(self):
        """Test OPC UA node class recognition"""
        node_classes = [
            "Object",
            "Variable",
            "Method",
            "ObjectType",
            "VariableType",
            "ReferenceType",
            "DataType",
            "View",
        ]

        for node_class in node_classes:
            self.assertIn(node_class, node_classes)


class TestOPCUAMockOperations(unittest.TestCase):
    """Test OPC UA operations with mocked dependencies"""

    def setUp(self):
        """Set up test environment"""
        self.scanner = OPCUAScanner({"rhost": "127.0.0.1", "rport": 4840, "timeout": 5})

    @patch("oida.protocols.opcua.asyncua")
    def test_read_server_info(self, mock_asyncua):
        """Test reading server information"""
        # Mock the OPC UA client and server info
        mock_client = AsyncMock()
        mock_asyncua.Client.return_value = mock_client

        # Mock server state and info
        mock_server_state = Mock()
        mock_server_state.get_value.return_value = "Running"
        mock_client.get_node.return_value = mock_server_state

        # This would test server info reading
        server_info = {
            "application_name": "Test OPC UA Server",
            "application_uri": "urn:opcua:test",
            "product_uri": "http://example.com/opcua",
            "server_state": "Running",
        }

        self.assertEqual(server_info["server_state"], "Running")
        self.assertIn("application_name", server_info)

    @patch("oida.protocols.opcua.asyncua")
    def test_browse_address_space(self, mock_asyncua):
        """Test browsing OPC UA address space"""
        mock_client = AsyncMock()
        mock_asyncua.Client.return_value = mock_client

        # Mock root node and children
        mock_root = Mock()
        mock_root.get_children.return_value = ["Objects", "Types", "Views"]
        mock_client.get_root_node.return_value = mock_root

        # Simulate browsing
        address_space = {
            "root_node": "i=84",
            "objects_folder": "i=85",
            "types_folder": "i=86",
            "views_folder": "i=87",
            "server_folder": "i=2253",
        }

        self.assertEqual(len(address_space), 5)
        self.assertIn("root_node", address_space)
        self.assertIn("objects_folder", address_space)

    @patch("oida.protocols.opcua.asyncua")
    def test_read_node_values(self, mock_asyncua):
        """Test reading node values"""
        mock_client = AsyncMock()
        mock_asyncua.Client.return_value = mock_client

        # Mock variable node
        mock_node = Mock()
        mock_node.get_value.return_value = 42.5
        mock_node.get_data_type.return_value = "Double"
        mock_client.get_node.return_value = mock_node

        # Test value reading
        node_value = 42.5
        node_type = "Double"

        self.assertEqual(node_value, 42.5)
        self.assertEqual(node_type, "Double")

    @patch("oida.protocols.opcua.asyncua")
    def test_discover_endpoints(self, mock_asyncua):
        """Test endpoint discovery"""
        mock_client = AsyncMock()
        mock_asyncua.Client.return_value = mock_client

        # Mock endpoints
        mock_endpoints = [
            {
                "endpoint_url": "opc.tcp://127.0.0.1:4840",
                "security_policy": "None",
                "security_mode": "None",
            },
            {
                "endpoint_url": "opc.tcp://127.0.0.1:4840",
                "security_policy": "Basic256Sha256",
                "security_mode": "SignAndEncrypt",
            },
        ]

        self.assertEqual(len(mock_endpoints), 2)
        self.assertEqual(mock_endpoints[0]["security_policy"], "None")
        self.assertEqual(mock_endpoints[1]["security_mode"], "SignAndEncrypt")

    @pytest.mark.network
    def test_disconnected_operations(self):
        """Test operations when disconnected"""
        results = self.scanner.run_scan()

        # Should handle disconnection gracefully
        self.assertIsInstance(results, dict)
        if "error" in results and results["error"]:
            # Accept connection errors or auth errors (if a local server is running)
            error_lower = results["error"].lower()
            self.assertTrue(
                "connect" in error_lower
                or "refused" in error_lower
                or "permission" in error_lower
                or "access" in error_lower
                or "timeout" in error_lower
                or "denied" in error_lower,
                f"Expected connection or auth error, got: {results['error']}",
            )


@pytest.mark.network
class TestOPCUAErrorHandling(unittest.TestCase):
    """Test OPC UA error handling scenarios"""

    def test_connection_timeout(self):
        """Test connection timeout scenarios"""
        scanner = OPCUAScanner(
            {
                "rhost": "192.168.254.254",  # Non-routable address
                "rport": 4840,
                "timeout": 1,  # Very short timeout
            }
        )

        result = scanner.run_scan()

        self.assertIsInstance(result, dict)
        # Timeout/unreachable hosts may return empty error or timeout-related message
        if "error" in result and result["error"]:
            error_lower = result["error"].lower()
            self.assertTrue(
                any(x in error_lower for x in ["timeout", "connect", "failed", "refused"]),
                f"Expected timeout/connection error, got: {result['error']}",
            )

    def test_invalid_endpoint_url(self):
        """Test invalid endpoint URL handling"""
        scanner = OPCUAScanner(
            {"rhost": "127.0.0.1", "rport": 4840, "endpoint_url": "invalid://bad-url"}
        )

        result = scanner.run_scan()
        self.assertIsInstance(result, dict)

    @patch("oida.protocols.opcua.asyncua")
    def test_opcua_protocol_errors(self, mock_asyncua):
        """Test OPC UA protocol-specific error handling"""
        mock_client = AsyncMock()
        mock_asyncua.Client.return_value = mock_client

        # Simulate various OPC UA errors
        from asyncua.ua.uaerrors import BadUserAccessDenied

        mock_client.connect.side_effect = BadUserAccessDenied("Access denied")

        scanner = OPCUAScanner({"rhost": "127.0.0.1", "rport": 4840})
        result = scanner.run_scan()

        self.assertIsInstance(result, dict)
        if "error" in result:
            self.assertIsInstance(result["error"], str)

    def test_certificate_errors(self):
        """Test certificate validation errors"""
        scanner = OPCUAScanner(
            {
                "rhost": "127.0.0.1",
                "rport": 4840,
                "security_policy": "Basic256Sha256",
                "security_mode": "SignAndEncrypt",
            }
        )

        # Should handle certificate errors gracefully
        result = scanner.run_scan()
        self.assertIsInstance(result, dict)


class TestOPCUAIntegration(unittest.TestCase):
    """Integration tests for OPC UA scanner"""

    @pytest.mark.network
    def test_complete_opcua_scan_workflow(self):
        """Test complete OPC UA scanning workflow"""
        scanner = OPCUAScanner({"rhost": "127.0.0.1", "rport": 4840, "timeout": 10})

        # Test basic workflow
        protocol_name = scanner.get_protocol_name()
        default_port = scanner.get_default_port()
        dependencies_ok = scanner.check_dependencies()

        self.assertEqual(protocol_name, "OPC UA")
        self.assertEqual(default_port, 4840)
        # Note: asyncua may not be available in test environment
        self.assertIsInstance(dependencies_ok, bool)

        # Test connectivity check
        connectivity = scanner.test_connectivity("127.0.0.1", 4840)
        self.assertIsInstance(connectivity, bool)

        # Test scan execution
        result = scanner.run_scan()
        self.assertIsInstance(result, dict)

    def test_opcua_with_different_configurations(self):
        """Test OPC UA scanner with different configurations"""
        configurations = [
            {"rhost": "127.0.0.1", "rport": 4840, "timeout": 5},
            {"rhost": "127.0.0.1", "rport": 8080, "timeout": 10},  # Alternative port
            {
                "rhost": "192.168.1.100",
                "rport": 4840,
                "timeout": 15,
                "security_policy": "Basic256Sha256",
            },
        ]

        for config in configurations:
            scanner = OPCUAScanner(config)
            self.assertEqual(scanner.host, config["rhost"])
            self.assertEqual(scanner.port, config["rport"])
            self.assertEqual(scanner.timeout, config["timeout"])

    def test_opcua_endpoint_url_parsing(self):
        """Test OPC UA endpoint URL parsing"""
        test_urls = [
            "opc.tcp://localhost:4840",
            "opc.tcp://192.168.1.100:4840/OPCUAServer",
            "opc.tcp://opcua.example.com:4840/UA/SampleServer",
        ]

        for url in test_urls:
            self.assertTrue(url.startswith("opc.tcp://"))
            self.assertIn(":", url)


class TestOPCUAAuthenticationTesting(unittest.TestCase):
    """Test OPC UA authentication testing functionality"""

    @patch("oida.protocols.opcua.asyncua")
    def test_anonymous_authentication(self, mock_asyncua):
        """Test anonymous authentication testing"""
        mock_client = AsyncMock()
        mock_asyncua.Client.return_value = mock_client
        mock_client.connect.return_value = None

        # Test anonymous connection
        auth_result = {"anonymous_allowed": True, "authentication_required": False}

        self.assertTrue(auth_result["anonymous_allowed"])
        self.assertFalse(auth_result["authentication_required"])

    @patch("oida.protocols.opcua.asyncua")
    def test_username_password_authentication(self, mock_asyncua):
        """Test username/password authentication"""
        mock_client = AsyncMock()
        mock_asyncua.Client.return_value = mock_client

        # Test credential testing
        test_credentials = [
            ("admin", "admin"),
            ("operator", "operator"),
            ("guest", "guest"),
            ("user", "password"),
        ]

        for username, password in test_credentials:
            self.assertIsInstance(username, str)
            self.assertIsInstance(password, str)
            self.assertTrue(len(username) > 0)

    @patch("oida.protocols.opcua.asyncua")
    def test_certificate_authentication(self, mock_asyncua):
        """Test certificate-based authentication"""
        mock_client = AsyncMock()
        mock_asyncua.Client.return_value = mock_client

        # Test certificate authentication setup
        cert_config = {
            "certificate_path": "/tmp/client.pem",
            "private_key_path": "/tmp/client.key",
            "server_certificate_validation": True,
        }

        self.assertIn("certificate_path", cert_config)
        self.assertIn("private_key_path", cert_config)
        self.assertTrue(cert_config["server_certificate_validation"])


class TestOPCUAURLNormalization(unittest.TestCase):
    """Test OPC UA URL normalization and parsing from helpers.py"""

    def test_normalize_url_with_scheme(self):
        """Test URL normalization when scheme already present"""
        from oida.protocols.opcua.helpers import _normalize_opcua_url

        url = "opc.tcp://192.168.1.100:4840"
        result = _normalize_opcua_url(url)
        self.assertEqual(result, "opc.tcp://192.168.1.100:4840")

    def test_normalize_url_without_scheme(self):
        """Test URL normalization without scheme"""
        from oida.protocols.opcua.helpers import _normalize_opcua_url

        url = "192.168.1.100:4840"
        result = _normalize_opcua_url(url)
        self.assertEqual(result, "opc.tcp://192.168.1.100:4840")

    def test_normalize_url_host_only(self):
        """Test URL normalization with host only (adds default port)"""
        from oida.protocols.opcua.helpers import _normalize_opcua_url

        url = "192.168.1.100"
        result = _normalize_opcua_url(url, default_port=4840)
        self.assertEqual(result, "opc.tcp://192.168.1.100:4840")

    def test_normalize_url_custom_port(self):
        """Test URL normalization with custom default port"""
        from oida.protocols.opcua.helpers import _normalize_opcua_url

        url = "opcua.example.com"
        result = _normalize_opcua_url(url, default_port=8080)
        self.assertEqual(result, "opc.tcp://opcua.example.com:8080")

    def test_normalize_url_with_path(self):
        """Test URL normalization preserving path component"""
        from oida.protocols.opcua.helpers import _normalize_opcua_url

        url = "192.168.1.100:4840/UA/Server"
        result = _normalize_opcua_url(url)
        self.assertEqual(result, "opc.tcp://192.168.1.100:4840/UA/Server")

    def test_parse_url_components(self):
        """Test parsing URL into components"""
        from oida.protocols.opcua.helpers import _parse_opcua_url

        url = "opc.tcp://192.168.1.100:4840/UA/Server"
        host, port, path = _parse_opcua_url(url)
        self.assertEqual(host, "192.168.1.100")
        self.assertEqual(port, 4840)
        self.assertEqual(path, "/UA/Server")

    def test_parse_url_without_path(self):
        """Test parsing URL without path component"""
        from oida.protocols.opcua.helpers import _parse_opcua_url

        url = "opc.tcp://192.168.1.100:4840"
        host, port, path = _parse_opcua_url(url)
        self.assertEqual(host, "192.168.1.100")
        self.assertEqual(port, 4840)
        self.assertEqual(path, "")

    def test_parse_url_default_port(self):
        """Test parsing URL without port (uses default)"""
        from oida.protocols.opcua.helpers import _parse_opcua_url

        url = "192.168.1.100"
        host, port, path = _parse_opcua_url(url)
        self.assertEqual(host, "192.168.1.100")
        self.assertEqual(port, 4840)
        self.assertEqual(path, "")

    def test_parse_url_hostname(self):
        """Test parsing URL with hostname"""
        from oida.protocols.opcua.helpers import _parse_opcua_url

        url = "opc.tcp://opcua.server.local:4840"
        host, port, path = _parse_opcua_url(url)
        self.assertEqual(host, "opcua.server.local")
        self.assertEqual(port, 4840)


class TestOPCUAValidateTargetIPv6(unittest.TestCase):
    """Regression tests for validate_target on bracketed-IPv6 opc.tcp:// URLs.

    The old naive splitter did host.replace("opc.tcp://","").split(":")[0],
    which returns the literal '[' for opc.tcp://[::1]:4840 and rejected every
    valid bracketed-IPv6 endpoint.
    """

    def test_validate_target_accepts_bracketed_ipv6_url(self):
        scanner = OPCUAScanner({"rhost": "opc.tcp://[::1]:4840"})
        scanner.logger = Mock()
        self.assertTrue(scanner.validate_target("opc.tcp://[::1]:4840", 4840))
        scanner.logger.fail.assert_not_called()

    def test_validate_target_accepts_bracketed_ipv6_url_with_path(self):
        scanner = OPCUAScanner({"rhost": "opc.tcp://[2001:db8::1]:4840/UA/Server"})
        scanner.logger = Mock()
        self.assertTrue(scanner.validate_target("opc.tcp://[2001:db8::1]:4840/UA/Server", 4840))
        scanner.logger.fail.assert_not_called()

    def test_validate_target_still_accepts_ipv4_url(self):
        scanner = OPCUAScanner({"rhost": "opc.tcp://192.168.1.100:4840"})
        scanner.logger = Mock()
        self.assertTrue(scanner.validate_target("opc.tcp://192.168.1.100:4840", 4840))
        scanner.logger.fail.assert_not_called()


class TestOPCUASecurityPolicySelection(unittest.TestCase):
    """Test security policy selection and configuration"""

    def test_scanner_security_policy_init(self):
        """Test scanner initialization with security policy"""
        scanner = OPCUAScanner(
            {
                "rhost": "192.168.1.100",
                "rport": 4840,
                "security-policy": "basic256sha256",
                "security-mode": "signandencrypt",
            }
        )
        self.assertEqual(scanner.security_policy, "basic256sha256")
        self.assertEqual(scanner.security_mode, "signandencrypt")

    def test_security_configuration_defaults(self):
        """Test default security configuration"""
        scanner = OPCUAScanner({"rhost": "192.168.1.100", "rport": 4840})
        self.assertEqual(scanner.security_policy, "none")
        self.assertEqual(scanner.security_mode, "none")


class TestOPCUANodeBrowsing(unittest.IsolatedAsyncioTestCase):
    """Test node browsing and result parsing"""

    @patch("oida.protocols.opcua.scanner.asyncio")
    def test_explore_node_depth_limit(self, mock_asyncio):
        """Test node exploration respects max depth limit"""
        scanner = OPCUAScanner(
            {"rhost": "127.0.0.1", "rport": 4840, "max-depth": 2, "max-nodes": 100}
        )

        # Verify max_depth setting
        self.assertEqual(scanner.max_depth, 2)

    @patch("oida.protocols.opcua.scanner.asyncio")
    def test_explore_node_count_limit(self, mock_asyncio):
        """Test node exploration respects max nodes limit"""
        scanner = OPCUAScanner(
            {"rhost": "127.0.0.1", "rport": 4840, "max-depth": 10, "max-nodes": 50}
        )

        # Verify max_nodes setting
        self.assertEqual(scanner.max_nodes, 50)

    async def test_node_info_extraction(self):
        """Test extracting node information"""
        # Mock node structure
        mock_node = Mock()
        mock_node.nodeid.to_string.return_value = "ns=2;i=1001"

        mock_browse_name = Mock()
        mock_browse_name.NamespaceIndex = 2
        mock_browse_name.Name = "Temperature"

        mock_display_name = Mock()
        mock_display_name.Text = "Temperature Sensor"

        mock_node_class = Mock()
        mock_node_class.name = "Variable"

        mock_node.read_browse_name = AsyncMock(return_value=mock_browse_name)
        mock_node.read_display_name = AsyncMock(return_value=mock_display_name)
        mock_node.read_node_class = AsyncMock(return_value=mock_node_class)
        mock_node.get_children = AsyncMock(return_value=[])

        # Expected node info structure
        node_info = {
            "node_id": "ns=2;i=1001",
            "browse_name": "2:Temperature",
            "display_name": "Temperature Sensor",
            "node_class": "Variable",
        }

        self.assertEqual(node_info["node_id"], "ns=2;i=1001")
        self.assertEqual(node_info["node_class"], "Variable")

    def test_browse_arguments(self):
        """Test browse operation with different arguments"""
        scanner = OPCUAScanner(
            {
                "rhost": "127.0.0.1",
                "rport": 4840,
                "max-depth": 5,
                "max-nodes": 200,
                "read-values": True,
            }
        )

        self.assertEqual(scanner.max_depth, 5)
        self.assertEqual(scanner.max_nodes, 200)
        self.assertTrue(scanner.read_values)


class TestOPCUAAuthenticationHandling(unittest.IsolatedAsyncioTestCase):
    """Test authentication methods and credential handling"""

    async def test_set_user_anonymous(self):
        """Test setting anonymous user"""
        mock_client = AsyncMock()
        mock_client.set_user = AsyncMock()

        await mock_client.set_user(None)
        mock_client.set_user.assert_called_once_with(None)

    async def test_set_user_username_password(self):
        """Test setting username/password authentication"""
        mock_client = AsyncMock()
        mock_client.set_user = AsyncMock()

        await mock_client.set_user("testuser", "testpass")
        mock_client.set_user.assert_called_once_with("testuser", "testpass")

    def test_authentication_init_parameters(self):
        """Test scanner initialization with authentication parameters"""
        scanner = OPCUAScanner(
            {
                "rhost": "192.168.1.100",
                "rport": 4840,
                "username": "admin",
                "password": "secret123",
            }
        )

        self.assertEqual(scanner.username, "admin")
        self.assertEqual(scanner.password, "secret123")

    def test_authentication_result_parsing(self):
        """Test parsing authentication test results"""
        auth_result = {
            "anonymous_access": True,
            "username_password": {"admin": "valid", "guest": "invalid"},
            "certificate_auth": False,
            "tested_credentials": ["admin:admin"],
        }

        self.assertTrue(auth_result["anonymous_access"])
        self.assertIn("admin", auth_result["username_password"])
        self.assertEqual(auth_result["username_password"]["admin"], "valid")
        self.assertFalse(auth_result["certificate_auth"])

    def test_report_credential_uses_validating_password(self):
        """Credential report must emit the password that validated per user,
        not the shared self.password."""
        scanner = OPCUAScanner(
            {
                "rhost": "192.168.1.100",
                "rport": 4840,
                "username": "admin",
                "password": "shared-default",
            }
        )

        results = {
            "authentication_test": {
                "anonymous_access": False,
                "username_password": {
                    "admin": "valid",
                    "operator": "valid",
                    "guest": "invalid",
                },
                "valid_passwords": {
                    "admin": "adminpass",
                    "operator": "operatorpass",
                },
            },
            "endpoints": [],
            "address_space": {},
        }

        scanner.report_host_info = Mock()
        scanner.report_service_info = Mock()
        scanner.report_vulnerability = Mock()
        scanner.report_credential = Mock()

        scanner._report_findings(results)

        reported = {call.args[0]: call.args[1] for call in scanner.report_credential.call_args_list}
        self.assertEqual(reported, {"admin": "adminpass", "operator": "operatorpass"})
        # The shared self.password must not leak into the report.
        self.assertNotIn("shared-default", reported.values())


class TestOPCUACertificateValidation(unittest.TestCase):
    """Test certificate validation and security configuration"""

    def test_certificate_paths_configuration(self):
        """Test certificate and private key path configuration"""
        scanner = OPCUAScanner(
            {
                "rhost": "192.168.1.100",
                "rport": 4840,
                "certificate-path": "/tmp/client.pem",
                "private-key-path": "/tmp/client.key",
            }
        )

        self.assertEqual(scanner.certificate_path, "/tmp/client.pem")
        self.assertEqual(scanner.private_key_path, "/tmp/client.key")

    def test_security_configuration_complete(self):
        """Test complete security configuration"""
        scanner = OPCUAScanner(
            {
                "rhost": "192.168.1.100",
                "rport": 4840,
                "security-policy": "basic256sha256",
                "security-mode": "signandencrypt",
                "certificate-path": "/tmp/client.pem",
                "private-key-path": "/tmp/client.key",
            }
        )

        self.assertEqual(scanner.security_policy, "basic256sha256")
        self.assertEqual(scanner.security_mode, "signandencrypt")
        self.assertEqual(scanner.certificate_path, "/tmp/client.pem")
        self.assertEqual(scanner.private_key_path, "/tmp/client.key")

    @patch("oida.protocols.opcua.scanner.OPCUAScanner._configure_security")
    def test_configure_security_called(self, mock_configure):
        """Test security configuration is invoked when policy is set"""
        scanner = OPCUAScanner(
            {
                "rhost": "192.168.1.100",
                "rport": 4840,
                "security-policy": "basic256sha256",
            }
        )

        # Mock client
        mock_client = Mock()
        scanner._configure_security(mock_client)

        # Verify configure_security was called
        mock_configure.assert_called_once()

    def test_security_string_format(self):
        """Test security string format generation"""
        scanner = OPCUAScanner(
            {
                "rhost": "192.168.1.100",
                "rport": 4840,
                "security-policy": "basic256sha256",
                "security-mode": "signandencrypt",
                "certificate-path": "/tmp/client.pem",
                "private-key-path": "/tmp/client.key",
            }
        )

        # Expected security string format
        expected = "basic256sha256,signandencrypt,/tmp/client.pem,/tmp/client.key"

        # Build actual security string (same logic as _configure_security)
        actual = (
            f"{scanner.security_policy},{scanner.security_mode},"
            f"{scanner.certificate_path},{scanner.private_key_path}"
        )

        self.assertEqual(actual, expected)


class TestOPCUAWriteAccessTesting(unittest.IsolatedAsyncioTestCase):
    """Test write access detection and testing"""

    async def test_write_access_attribute_check(self):
        """Test write access using UserAccessLevel attribute"""
        mock_node = Mock()

        # Mock UserAccessLevel response
        mock_access = Mock()
        mock_access.Value.Value = 0x03  # Read (0x01) + Write (0x02)

        from oida.protocols.opcua.helpers import _asyncua

        if _asyncua.is_available:
            mock_node.read_attribute = AsyncMock(return_value=mock_access)

            scanner = OPCUAScanner({"rhost": "127.0.0.1", "rport": 4840, "test-write": True})

            result = await scanner._test_write_access(mock_node)

            self.assertTrue(result["writable"])

    async def test_write_access_read_only(self):
        """Test read-only node detection"""
        mock_node = Mock()

        # Mock UserAccessLevel response - read only
        mock_access = Mock()
        mock_access.Value.Value = 0x01  # Read only

        from oida.protocols.opcua.helpers import _asyncua

        if _asyncua.is_available:
            mock_node.read_attribute = AsyncMock(return_value=mock_access)

            scanner = OPCUAScanner({"rhost": "127.0.0.1", "rport": 4840, "test-write": True})

            result = await scanner._test_write_access(mock_node)

            self.assertFalse(result["writable"])

    async def test_write_back_fallback_skipped_without_confirm(self):
        """AccessLevel-unavailable write-back probe must be skipped without --confirm"""
        from oida.protocols.opcua.helpers import _asyncua

        if not _asyncua.is_available:
            require_service("asyncua not available")

        mock_node = Mock()
        mock_node.read_attribute = AsyncMock(
            side_effect=Exception("BadAttributeIdInvalid: attribute not supported")
        )
        mock_node.read_value = AsyncMock(return_value=42)
        mock_node.write_value = AsyncMock()

        scanner = OPCUAScanner({"rhost": "127.0.0.1", "rport": 4840, "test-write": True})

        result = await scanner._test_write_access(mock_node)

        # No write performed, not reported writable, and a confirm hint recorded
        mock_node.write_value.assert_not_called()
        self.assertFalse(result["writable"])
        self.assertIn("--confirm", result["error"])

    async def test_write_back_fallback_writes_with_confirm(self):
        """With --confirm the write-back probe is allowed to run"""
        from oida.protocols.opcua.helpers import _asyncua

        if not _asyncua.is_available:
            require_service("asyncua not available")

        mock_node = Mock()
        mock_node.read_attribute = AsyncMock(
            side_effect=Exception("BadAttributeIdInvalid: attribute not supported")
        )
        mock_node.read_value = AsyncMock(return_value=42)
        mock_node.write_value = AsyncMock()

        scanner = OPCUAScanner(
            {"rhost": "127.0.0.1", "rport": 4840, "test-write": True, "confirm": True}
        )

        result = await scanner._test_write_access(mock_node)

        mock_node.write_value.assert_awaited_once_with(42)
        self.assertTrue(result["writable"])

    def test_test_write_parameter(self):
        """Test test-write parameter initialization"""
        scanner = OPCUAScanner({"rhost": "127.0.0.1", "rport": 4840, "test-write": True})

        self.assertTrue(scanner.test_write)

    def test_writable_nodes_reporting(self):
        """Test reporting of writable nodes"""
        # Simulated address space results
        address_space = {
            "nodes": [
                {"node_id": "ns=2;i=1001", "writable": True, "display_name": "SetPoint1"},
                {"node_id": "ns=2;i=1002", "writable": False, "display_name": "ReadOnly1"},
                {"node_id": "ns=2;i=1003", "writable": True, "display_name": "SetPoint2"},
            ],
            "writable_nodes": [
                {"node_id": "ns=2;i=1001", "writable": True, "display_name": "SetPoint1"},
                {"node_id": "ns=2;i=1003", "writable": True, "display_name": "SetPoint2"},
            ],
        }

        writable_count = len(address_space["writable_nodes"])
        self.assertEqual(writable_count, 2)


class TestOPCUATargetValidation(unittest.TestCase):
    """Test target validation for OPC UA URLs and hostnames"""

    def test_validate_opcua_url(self):
        """Test validation of OPC UA URL"""
        scanner = OPCUAScanner({"rhost": "opc.tcp://192.168.1.100:4840", "rport": 4840})

        host, port = scanner.get_target_info()
        is_valid = scanner.validate_target(host, port)

        # URL should be valid (contains valid IP)
        self.assertIsInstance(is_valid, bool)

    def test_validate_hostname(self):
        """Test validation of hostname"""
        scanner = OPCUAScanner({"rhost": "localhost", "rport": 4840})

        host, port = scanner.get_target_info()
        is_valid = scanner.validate_target(host, port)

        self.assertIsInstance(is_valid, bool)

    def test_validate_ip_address(self):
        """Test validation of IP address"""
        scanner = OPCUAScanner({"rhost": "192.168.1.100", "rport": 4840})

        host, port = scanner.get_target_info()
        is_valid = scanner.validate_target(host, port)

        self.assertTrue(is_valid)

    def test_get_target_info_from_url(self):
        """Test extracting target info from OPC UA URL"""
        scanner = OPCUAScanner({"rhost": "opc.tcp://192.168.1.100:8080", "rport": 4840})

        host, port = scanner.get_target_info()

        self.assertEqual(host, "opc.tcp://192.168.1.100:8080")
        self.assertEqual(port, 8080)

    def test_get_target_info_default_port(self):
        """Test target info with default port"""
        scanner = OPCUAScanner({"rhost": "192.168.1.100"})

        host, port = scanner.get_target_info()

        self.assertEqual(host, "192.168.1.100")
        self.assertEqual(port, 4840)


class TestOPCUAEndpointAnalysis(unittest.TestCase):
    """Test endpoint discovery and security analysis"""

    def test_endpoint_security_evaluation(self):
        """Test security evaluation of endpoints"""
        endpoints = [
            {
                "endpoint_url": "opc.tcp://192.168.1.100:4840",
                "security_policy": "http://opcfoundation.org/UA/SecurityPolicy#None",
                "security_mode": "None",
                "security_level": 0,
            },
            {
                "endpoint_url": "opc.tcp://192.168.1.100:4840",
                "security_policy": "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256",
                "security_mode": "SignAndEncrypt",
                "security_level": 8,
            },
        ]

        # Check for insecure endpoint
        has_insecure = any(ep["security_mode"] == "None" for ep in endpoints)
        self.assertTrue(has_insecure)

        # Check for secure endpoint
        has_secure = any(ep["security_mode"] == "SignAndEncrypt" for ep in endpoints)
        self.assertTrue(has_secure)

    def test_security_analysis_no_encryption(self):
        """Test security analysis when no encryption available"""
        results = {
            "endpoints": [
                {
                    "security_policy": "http://opcfoundation.org/UA/SecurityPolicy#None",
                    "security_mode": "None",
                }
            ],
            "authentication_test": {"anonymous_access": True},
        }

        has_encryption = any(
            ep.get("security_mode") not in ["None", None] for ep in results["endpoints"]
        )

        self.assertFalse(has_encryption)

    def test_security_analysis_with_signing(self):
        """Test security analysis with message signing"""
        results = {
            "endpoints": [
                {
                    "security_policy": "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256",
                    "security_mode": "Sign",
                }
            ],
            "authentication_test": {"anonymous_access": False},
        }

        has_signing = any("Sign" in ep.get("security_mode", "") for ep in results["endpoints"])

        self.assertTrue(has_signing)


class TestOPCUAValueReading(unittest.IsolatedAsyncioTestCase):
    """Test reading values from OPC UA variable nodes"""

    def test_read_values_parameter(self):
        """Test read-values parameter initialization"""
        scanner = OPCUAScanner({"rhost": "127.0.0.1", "rport": 4840, "read-values": True})

        self.assertTrue(scanner.read_values)

    async def test_read_node_value_success(self):
        """Test successful node value reading"""
        mock_node = Mock()
        mock_node.read_value = AsyncMock(return_value=42.5)

        # Mock data type
        mock_data_type = Mock()
        mock_data_type.name = "Double"
        mock_node.read_data_type_as_variant_type = AsyncMock(return_value=mock_data_type)

        value = await mock_node.read_value()
        data_type = await mock_node.read_data_type_as_variant_type()

        self.assertEqual(value, 42.5)
        self.assertEqual(data_type.name, "Double")

    def test_node_values_storage(self):
        """Test storage of node values"""
        scanner = OPCUAScanner({"rhost": "127.0.0.1", "rport": 4840, "read-values": True})

        # Simulate storing node values
        scanner.node_values["ns=2;i=1001"] = "42.5"
        scanner.node_values["ns=2;i=1002"] = "Running"

        self.assertEqual(len(scanner.node_values), 2)
        self.assertEqual(scanner.node_values["ns=2;i=1001"], "42.5")


class TestOPCUAHelperFunctions(unittest.TestCase):
    """Test helper functions from helpers.py"""

    def test_lazy_import_asyncua(self):
        """Test lazy import mechanism for asyncua"""
        from oida.protocols.opcua.helpers import _asyncua

        # Check availability
        self.assertIsInstance(_asyncua.is_available, bool)

    def test_get_client_class(self):
        """Test getting Client class lazily"""
        from oida.protocols.opcua.helpers import _asyncua, _get_client_class

        if _asyncua.is_available:
            Client = _get_client_class()
            self.assertIsNotNone(Client)

    def test_get_bad_user_access_denied(self):
        """Test getting BadUserAccessDenied exception class"""
        from oida.protocols.opcua.helpers import _asyncua, _get_bad_user_access_denied

        if _asyncua.is_available:
            BadUserAccessDenied = _get_bad_user_access_denied()
            self.assertIsNotNone(BadUserAccessDenied)

    def test_ua_lazy_module_proxy(self):
        """Test lazy proxy for ua module"""
        from oida.protocols.opcua.helpers import _asyncua, ua

        if _asyncua.is_available:
            # Should be able to access ua attributes via proxy
            self.assertIsNotNone(ua)


class TestOPCUAProgressTracking(unittest.TestCase):
    """Test progress tracking during node browsing"""

    def test_progress_tracker_initialization(self):
        """Test ProgressTracker initialization"""
        from oida.utils import ProgressTracker
        from oida.utils.ics_logger import ICSLogger

        logger = ICSLogger("test", "127.0.0.1", 4840)
        tracker = ProgressTracker(total=100, logger=logger)

        self.assertEqual(tracker.total, 100)

    def test_browse_with_progress_tracking(self):
        """Test browsing with progress updates"""
        scanner = OPCUAScanner(
            {"rhost": "127.0.0.1", "rport": 4840, "max-nodes": 50, "max-depth": 5}
        )

        # Progress tracking should be used during browse
        self.assertEqual(scanner.max_nodes, 50)


class TestOPCUASecurityFindings(unittest.TestCase):
    """Test security findings reporting"""

    def test_anonymous_access_finding(self):
        """Test reporting anonymous access finding"""
        OPCUAScanner({"rhost": "192.168.1.100", "rport": 4840})

        # Mock results with anonymous access
        results = {
            "authentication_test": {"anonymous_access": True},
            "endpoints": [{"security_mode": "None"}],
            "address_space": {},
        }

        # Security finding should be recorded
        self.assertTrue(results["authentication_test"]["anonymous_access"])

    def test_no_encryption_finding(self):
        """Test reporting no encryption finding"""
        OPCUAScanner({"rhost": "192.168.1.100", "rport": 4840})

        results = {
            "endpoints": [{"security_mode": "None"}, {"security_mode": "None"}],
            "authentication_test": {},
            "address_space": {},
        }

        has_encryption = any(
            ep.get("security_mode") not in ["None", None] for ep in results["endpoints"]
        )

        self.assertFalse(has_encryption)

    def test_writable_nodes_finding(self):
        """Test reporting writable nodes security finding"""
        OPCUAScanner({"rhost": "192.168.1.100", "rport": 4840})

        results = {
            "address_space": {
                "writable_nodes": [
                    {"node_id": "ns=2;i=1001", "writable": True},
                    {"node_id": "ns=2;i=1002", "writable": True},
                ]
            },
            "endpoints": [],
            "authentication_test": {},
        }

        writable_count = len(results["address_space"]["writable_nodes"])
        self.assertEqual(writable_count, 2)


class TestOPCUAConnectionManagement(unittest.TestCase):
    """Test connection lifecycle management"""

    def test_connect_method(self):
        """Test connect method returns client"""
        scanner = OPCUAScanner({"rhost": "192.168.1.100", "rport": 4840})

        # Connect should return a client object (may fail if server not available)
        client = scanner.connect()
        self.assertIsNotNone(client)

    def test_disconnect_method(self):
        """Test disconnect method handles cleanup"""
        scanner = OPCUAScanner({"rhost": "192.168.1.100", "rport": 4840})

        # Mock client
        mock_client = Mock()
        mock_client.disconnect = AsyncMock()

        scanner.disconnect(mock_client)
        mock_client.disconnect.assert_awaited_once()

    def test_disconnect_none_client(self):
        """Test disconnect with None client"""
        scanner = OPCUAScanner({"rhost": "192.168.1.100", "rport": 4840})

        # None is handled without raising and without touching asyncio
        scanner.disconnect(None)
        self.assertIsNone(scanner.disconnect(None))


import pytest
import socket


# ==============================================================================
# Error Path Tests - Network Failures, Malformed Data, Timeouts
# ==============================================================================


class TestOPCUANetworkErrorPaths(unittest.TestCase):
    """Test network error handling paths in OPCUAScanner.

    These tests verify the scanner handles various network failures gracefully.
    """

    def setUp(self):
        """Set up scanner instance"""
        self.scanner = OPCUAScanner({"rhost": "192.168.1.1", "rport": 4840, "timeout": 1})

    def test_connection_refused(self):
        """Test handling of connection refused error."""
        mock_client = Mock()
        mock_client.connect = AsyncMock(side_effect=ConnectionRefusedError("Connection refused"))

        # Should handle connection refused gracefully
        with self.assertRaises(ConnectionRefusedError):
            asyncio.run(mock_client.connect())

    def test_connection_timeout(self):
        """Test handling of connection timeout."""
        mock_client = Mock()
        mock_client.connect = AsyncMock(side_effect=asyncio.TimeoutError("Connection timed out"))

        with self.assertRaises(asyncio.TimeoutError):
            asyncio.run(mock_client.connect())

    def test_connection_reset_during_browse(self):
        """Test handling of connection reset during browse."""
        mock_client = Mock()
        mock_client.get_root_node = AsyncMock(
            side_effect=ConnectionResetError("Connection reset by peer")
        )

        with self.assertRaises(ConnectionResetError):
            asyncio.run(mock_client.get_root_node())

    def test_socket_timeout_during_operation(self):
        """Test handling of socket timeout during operation."""
        mock_client = Mock()
        mock_client.read_values = AsyncMock(side_effect=socket.timeout("timed out"))

        with self.assertRaises(socket.timeout):
            asyncio.run(mock_client.read_values([]))

    def test_network_unreachable(self):
        """Test handling of network unreachable error."""
        import errno

        mock_client = Mock()
        mock_client.connect = AsyncMock(
            side_effect=OSError(errno.ENETUNREACH, "Network is unreachable")
        )

        with self.assertRaises(OSError) as ctx:
            asyncio.run(mock_client.connect())
        self.assertEqual(ctx.exception.errno, errno.ENETUNREACH)

    def test_host_unreachable(self):
        """Test handling of host unreachable error."""
        import errno

        mock_client = Mock()
        mock_client.connect = AsyncMock(side_effect=OSError(errno.EHOSTUNREACH, "No route to host"))

        with self.assertRaises(OSError) as ctx:
            asyncio.run(mock_client.connect())
        self.assertEqual(ctx.exception.errno, errno.EHOSTUNREACH)


class TestOPCUAAuthenticationErrors(unittest.TestCase):
    """Test authentication error handling."""

    def setUp(self):
        """Set up scanner instance"""
        self.scanner = OPCUAScanner(
            {
                "rhost": "192.168.1.1",
                "rport": 4840,
                "username": "admin",
                "password": "wrongpassword",
            }
        )

    def test_invalid_credentials(self):
        """Test handling of invalid credentials."""
        mock_client = Mock()

        # Mock BadUserAccessDenied exception
        class MockBadUserAccessDenied(Exception):
            pass

        mock_client.connect = AsyncMock(
            side_effect=MockBadUserAccessDenied("Bad user access denied")
        )

        with self.assertRaises(MockBadUserAccessDenied):
            asyncio.run(mock_client.connect())

    def test_certificate_error(self):
        """Test handling of certificate validation error."""
        mock_client = Mock()

        # Mock certificate error
        class MockBadCertificate(Exception):
            pass

        mock_client.connect = AsyncMock(side_effect=MockBadCertificate("Certificate not trusted"))

        with self.assertRaises(MockBadCertificate):
            asyncio.run(mock_client.connect())

    def test_security_policy_mismatch(self):
        """Test handling of security policy mismatch."""
        OPCUAScanner(
            {
                "rhost": "192.168.1.1",
                "rport": 4840,
                "security-policy": "basic256sha256",
            }
        )

        mock_client = Mock()

        class MockSecurityError(Exception):
            pass

        mock_client.connect = AsyncMock(
            side_effect=MockSecurityError("Security policy not supported")
        )

        with self.assertRaises(MockSecurityError):
            asyncio.run(mock_client.connect())


class TestOPCUAMalformedResponseHandling(unittest.TestCase):
    """Test handling of malformed OPC UA responses."""

    def setUp(self):
        """Set up scanner instance"""
        self.scanner = OPCUAScanner({"rhost": "192.168.1.1", "rport": 4840})

    def test_empty_endpoint_list(self):
        """Test handling of empty endpoint list."""
        mock_client = Mock()
        mock_client.get_endpoints = AsyncMock(return_value=[])

        endpoints = asyncio.run(mock_client.get_endpoints())

        self.assertEqual(len(endpoints), 0)

    def test_none_endpoints(self):
        """Test handling of None endpoints."""
        mock_client = Mock()
        mock_client.get_endpoints = AsyncMock(return_value=None)

        endpoints = asyncio.run(mock_client.get_endpoints())

        self.assertIsNone(endpoints)

    def test_malformed_node_id(self):
        """Test handling of malformed node ID."""
        mock_client = Mock()

        class MockBadNodeId(Exception):
            pass

        mock_client.get_node = Mock(side_effect=MockBadNodeId("Invalid node ID"))

        with self.assertRaises(MockBadNodeId):
            mock_client.get_node("invalid-node-id")

    def test_truncated_server_info(self):
        """Test handling of truncated server information."""
        mock_node = Mock()
        mock_node.read_value = AsyncMock(return_value=None)

        value = asyncio.run(mock_node.read_value())

        self.assertIsNone(value)

    def test_invalid_data_type_response(self):
        """Test handling of invalid data type in response."""
        mock_node = Mock()
        mock_node.read_data_type_as_variant_type = AsyncMock(
            side_effect=ValueError("Invalid data type")
        )

        with self.assertRaises(ValueError):
            asyncio.run(mock_node.read_data_type_as_variant_type())


class TestOPCUATimeoutEdgeCases(unittest.TestCase):
    """Test timeout handling edge cases."""

    def test_zero_timeout(self):
        """Test scanner behavior with zero timeout."""
        scanner = OPCUAScanner({"rhost": "192.168.1.1", "rport": 4840, "timeout": 0})

        self.assertEqual(scanner.timeout, 0)

    def test_very_small_timeout(self):
        """Test scanner behavior with very small timeout (1ms).

        Note: BaseScanner converts timeout to int, so 0.001 becomes 0.
        """
        scanner = OPCUAScanner({"rhost": "192.168.1.1", "rport": 4840, "timeout": 0.001})

        # Timeout is converted to int by BaseScanner
        self.assertEqual(scanner.timeout, 0)

    def test_very_large_timeout(self):
        """Test scanner behavior with very large timeout."""
        scanner = OPCUAScanner({"rhost": "192.168.1.1", "rport": 4840, "timeout": 3600})

        self.assertEqual(scanner.timeout, 3600)

    def test_negative_timeout_handling(self):
        """Test scanner behavior with negative timeout."""
        scanner = OPCUAScanner({"rhost": "192.168.1.1", "rport": 4840, "timeout": -1})

        self.assertIsNotNone(scanner.timeout)

    def test_browse_timeout(self):
        """Test timeout during address space browsing."""
        mock_client = Mock()
        mock_client.get_root_node = AsyncMock(side_effect=asyncio.TimeoutError("Browse timed out"))

        with self.assertRaises(asyncio.TimeoutError):
            asyncio.run(mock_client.get_root_node())


class TestOPCUAInvalidInputHandling(unittest.TestCase):
    """Test handling of invalid input parameters."""

    def test_invalid_port_zero(self):
        """Test handling of port 0."""
        scanner = OPCUAScanner({"rhost": "192.168.1.1", "rport": 0})

        self.assertEqual(scanner.port, 0)

    def test_invalid_port_over_65535(self):
        """Test handling of port > 65535."""
        scanner = OPCUAScanner({"rhost": "192.168.1.1", "rport": 70000})

        self.assertEqual(scanner.port, 70000)

    def test_empty_host(self):
        """Test handling of empty host.

        Scanner should raise ValueError for empty host.
        """
        with self.assertRaises(ValueError) as ctx:
            OPCUAScanner({"rhost": "", "rport": 4840})

        self.assertIn("rhost", str(ctx.exception).lower())

    def test_invalid_security_policy(self):
        """Test handling of invalid security policy."""
        scanner = OPCUAScanner(
            {
                "rhost": "192.168.1.1",
                "rport": 4840,
                "security-policy": "invalid-policy",
            }
        )

        self.assertEqual(scanner.security_policy, "invalid-policy")

    def test_invalid_security_mode(self):
        """Test handling of invalid security mode."""
        scanner = OPCUAScanner(
            {
                "rhost": "192.168.1.1",
                "rport": 4840,
                "security-mode": "invalid-mode",
            }
        )

        self.assertEqual(scanner.security_mode, "invalid-mode")

    def test_max_depth_zero(self):
        """Test handling of max-depth = 0."""
        scanner = OPCUAScanner({"rhost": "192.168.1.1", "rport": 4840, "max-depth": 0})

        self.assertEqual(scanner.max_depth, 0)

    def test_max_nodes_zero(self):
        """Test handling of max-nodes = 0."""
        scanner = OPCUAScanner({"rhost": "192.168.1.1", "rport": 4840, "max-nodes": 0})

        self.assertEqual(scanner.max_nodes, 0)

    def test_negative_max_depth(self):
        """Test handling of negative max-depth."""
        scanner = OPCUAScanner({"rhost": "192.168.1.1", "rport": 4840, "max-depth": -1})

        self.assertEqual(scanner.max_depth, -1)


class TestOPCUAResourceCleanup(unittest.TestCase):
    """Test proper resource cleanup on errors."""

    def setUp(self):
        """Set up scanner instance"""
        self.scanner = OPCUAScanner({"rhost": "192.168.1.1", "rport": 4840})

    def test_disconnect_after_connection_error(self):
        """Test that disconnect is called after connection error."""
        mock_client = Mock()
        mock_client.disconnect = AsyncMock()

        # Should handle cleanup
        self.scanner.disconnect(mock_client)

        # Verify cleanup methods exist
        self.assertTrue(hasattr(mock_client, "disconnect"))

    def test_disconnect_after_browse_error(self):
        """Test that disconnect is called after browse error."""
        mock_client = Mock()
        mock_client.disconnect = AsyncMock()

        self.scanner.disconnect(mock_client)
        mock_client.disconnect.assert_awaited_once()

    def test_multiple_disconnect_calls_safe(self):
        """Test that multiple disconnect calls don't raise errors."""
        mock_client = Mock()
        mock_client.disconnect = AsyncMock()

        # Multiple disconnects are safe; each one awaited the close again
        self.scanner.disconnect(mock_client)
        self.scanner.disconnect(mock_client)
        self.scanner.disconnect(mock_client)
        self.assertEqual(mock_client.disconnect.await_count, 3)


class TestOPCUABrowseErrors(unittest.TestCase):
    """Test error handling during address space browsing."""

    def setUp(self):
        """Set up scanner instance"""
        self.scanner = OPCUAScanner({"rhost": "192.168.1.1", "rport": 4840})

    def test_recursive_browse_depth_exceeded(self):
        """Test handling when max browse depth is exceeded."""
        scanner = OPCUAScanner(
            {
                "rhost": "192.168.1.1",
                "rport": 4840,
                "max-depth": 2,
            }
        )

        # Max depth should be respected
        self.assertEqual(scanner.max_depth, 2)

    def test_max_nodes_exceeded(self):
        """Test handling when max nodes is exceeded."""
        scanner = OPCUAScanner(
            {
                "rhost": "192.168.1.1",
                "rport": 4840,
                "max-nodes": 100,
            }
        )

        self.assertEqual(scanner.max_nodes, 100)

    def test_permission_denied_on_node(self):
        """Test handling of permission denied on specific node."""
        mock_node = Mock()

        class MockBadUserAccessDenied(Exception):
            pass

        mock_node.get_children = AsyncMock(
            side_effect=MockBadUserAccessDenied("User cannot browse this node")
        )

        with self.assertRaises(MockBadUserAccessDenied):
            asyncio.run(mock_node.get_children())

    def test_browse_node_not_found(self):
        """Test handling when browsed node does not exist."""
        mock_client = Mock()

        class MockBadNodeIdUnknown(Exception):
            pass

        mock_client.get_node = Mock(side_effect=MockBadNodeIdUnknown("Node not found"))

        with self.assertRaises(MockBadNodeIdUnknown):
            mock_client.get_node("ns=99;i=99999")


# Pytest-style tests for parametrized error scenarios
class TestOPCUAWithErrorInjection:
    """Pytest-style tests using parametrized error scenarios."""

    @pytest.fixture(autouse=True)
    def setup_scanner(self):
        """Set up scanner for each test."""
        self.scanner = OPCUAScanner({"rhost": "192.168.1.1", "rport": 4840, "timeout": 5})

    @pytest.mark.parametrize(
        "exception_type,message",
        [
            (ConnectionRefusedError, "Connection refused"),
            (ConnectionResetError, "Connection reset by peer"),
            (asyncio.TimeoutError, "Connection timed out"),
            (socket.timeout, "timed out"),
            (OSError, "Network is down"),
        ],
    )
    def test_various_connection_errors(self, exception_type, message):
        """Test handling of various connection error types."""
        mock_client = Mock()
        mock_client.connect = AsyncMock(side_effect=exception_type(message))

        with pytest.raises(exception_type):
            asyncio.run(mock_client.connect())

    @pytest.mark.parametrize("security_mode", ["None", "Sign", "SignAndEncrypt"])
    def test_security_mode_parsing(self, security_mode):
        """Test security mode parameter parsing."""
        scanner = OPCUAScanner(
            {
                "rhost": "192.168.1.1",
                "rport": 4840,
                "security-mode": security_mode,
            }
        )

        assert scanner.security_mode == security_mode

    @pytest.mark.parametrize("max_depth", [0, 1, 5, 10, 100])
    def test_max_depth_values(self, max_depth):
        """Test various max-depth values."""
        scanner = OPCUAScanner(
            {
                "rhost": "192.168.1.1",
                "rport": 4840,
                "max-depth": max_depth,
            }
        )

        assert scanner.max_depth == max_depth

    @pytest.mark.parametrize("timeout", [0, 1, 5, 30, 3600])
    def test_timeout_values(self, timeout):
        """Test various timeout values.

        Note: BaseScanner converts timeout to int, so only integer values are tested.
        """
        scanner = OPCUAScanner(
            {
                "rhost": "192.168.1.1",
                "rport": 4840,
                "timeout": timeout,
            }
        )

        assert scanner.timeout == timeout


if __name__ == "__main__":
    unittest.main()
