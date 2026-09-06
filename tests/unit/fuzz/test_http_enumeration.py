"""
Test HTTP Fuzzer Enumeration/Probing Functionality

Tests the capability detection that probes servers before fuzzing
to detect supported HTTP methods and WebDAV.
"""

import pytest

from oida.fuzz.core.config import FuzzerConfig
from oida.fuzz.protocols.http_protocol import HTTPFuzzer
from oida.fuzz.core.connections import MockConnectionFactory


@pytest.fixture
def mock_config():
    """Create a mock FuzzerConfig for testing."""
    return FuzzerConfig(
        target_ip="127.0.0.1",
        target_port=8080,
        protocol="http",
        log_session=False,
        enumerate=True,
    )


@pytest.fixture
def mock_connection_factory():
    """Create a MockConnectionFactory for testing."""
    return MockConnectionFactory()


class TestHTTPProbeCapabilities:
    """Test HTTP server capability probing."""

    def test_parse_options_response_with_allow_header(self, mock_config, mock_connection_factory):
        """Test parsing OPTIONS response with Allow header."""
        fuzzer = HTTPFuzzer(mock_config, mock_connection_factory)

        response = (
            "HTTP/1.1 200 OK\r\n"
            "Server: Apache/2.4.52\r\n"
            "Allow: GET, HEAD, POST, OPTIONS\r\n"
            "Content-Length: 0\r\n"
            "\r\n"
        )

        capabilities = {"methods": set(), "webdav": False, "server": None}
        fuzzer._parse_http_response(response, capabilities)

        assert capabilities["server"] == "Apache/2.4.52"
        assert "GET" in capabilities["methods"]
        assert "HEAD" in capabilities["methods"]
        assert "POST" in capabilities["methods"]
        assert "OPTIONS" in capabilities["methods"]

    def test_parse_webdav_detection_from_allow(self, mock_config, mock_connection_factory):
        """Test WebDAV detection from Allow header."""
        fuzzer = HTTPFuzzer(mock_config, mock_connection_factory)

        response = "HTTP/1.1 200 OK\r\nServer: nginx\r\nAllow: GET, HEAD, PROPFIND, MKCOL\r\n\r\n"

        capabilities = {"methods": set(), "webdav": False, "server": None}
        fuzzer._parse_http_response(response, capabilities)

        assert capabilities["webdav"] is True
        assert "PROPFIND" in capabilities["methods"]
        assert "MKCOL" in capabilities["methods"]

    def test_parse_webdav_detection_from_dav_header(self, mock_config, mock_connection_factory):
        """Test WebDAV detection from DAV header."""
        fuzzer = HTTPFuzzer(mock_config, mock_connection_factory)

        response = "HTTP/1.1 200 OK\r\nServer: nginx\r\nDAV: 1, 2\r\nAllow: GET, HEAD\r\n\r\n"

        capabilities = {"methods": set(), "webdav": False, "server": None}
        fuzzer._parse_http_response(response, capabilities)

        assert capabilities["webdav"] is True

    def test_get_status_code_parsing(self, mock_config, mock_connection_factory):
        """Test HTTP status code extraction."""
        fuzzer = HTTPFuzzer(mock_config, mock_connection_factory)

        assert fuzzer._get_status_code("HTTP/1.1 200 OK\r\n") == 200
        assert fuzzer._get_status_code("HTTP/1.1 404 Not Found\r\n") == 404
        assert fuzzer._get_status_code("HTTP/1.1 501 Not Implemented\r\n") == 501
        assert fuzzer._get_status_code("HTTP/1.0 405 Method Not Allowed\r\n") == 405
        assert fuzzer._get_status_code("invalid response") is None
        assert fuzzer._get_status_code("") is None

    def test_supports_method_with_detected_methods(self, mock_config, mock_connection_factory):
        """Test _supports_method with detected capabilities."""
        fuzzer = HTTPFuzzer(mock_config, mock_connection_factory)
        fuzzer.capabilities = {"methods": {"GET", "HEAD", "POST"}}

        assert fuzzer._supports_method("GET") is True
        assert fuzzer._supports_method("HEAD") is True
        assert fuzzer._supports_method("POST") is True
        assert fuzzer._supports_method("DELETE") is False
        assert fuzzer._supports_method("PROPFIND") is False

    def test_supports_method_when_enumeration_disabled(self, mock_connection_factory):
        """Test _supports_method when enumeration is disabled."""
        config = FuzzerConfig(
            target_ip="127.0.0.1",
            target_port=8080,
            protocol="http",
            log_session=False,
            enumerate=False,
        )
        fuzzer = HTTPFuzzer(config, mock_connection_factory)

        # Should return True for all methods when enumeration disabled
        assert fuzzer._supports_method("GET") is True
        assert fuzzer._supports_method("DELETE") is True
        assert fuzzer._supports_method("PROPFIND") is True

    def test_supports_webdav_detection(self, mock_config, mock_connection_factory):
        """Test _supports_webdav method."""
        fuzzer = HTTPFuzzer(mock_config, mock_connection_factory)

        # No WebDAV detected
        fuzzer.capabilities = {"webdav": False}
        assert fuzzer._supports_webdav() is False

        # WebDAV detected
        fuzzer.capabilities = {"webdav": True}
        assert fuzzer._supports_webdav() is True

    def test_user_method_override(self, mock_connection_factory):
        """Test user can override detected methods."""
        config = FuzzerConfig(
            target_ip="127.0.0.1",
            target_port=8080,
            protocol="http",
            log_session=False,
            enumerate=True,
            protocol_options={"methods": "GET,POST,DELETE"},
        )
        HTTPFuzzer(config, mock_connection_factory)

        # User override should work regardless of detection
        # The actual filtering happens in _define_protocol
        assert config.get_option("methods") == "GET,POST,DELETE"

    def test_user_webdav_override(self, mock_connection_factory):
        """Test user can force WebDAV on/off."""
        config = FuzzerConfig(
            target_ip="127.0.0.1",
            target_port=8080,
            protocol="http",
            log_session=False,
            enumerate=True,
            protocol_options={"webdav": True},
        )
        HTTPFuzzer(config, mock_connection_factory)

        assert config.get_option("webdav") is True


class TestHTTPEnumerationConfig:
    """Test enumeration configuration options."""

    def test_enumerate_enabled_by_default(self):
        """Test that enumeration is enabled by default."""
        config = FuzzerConfig(
            target_ip="127.0.0.1",
            target_port=8080,
            protocol="http",
        )
        assert config.enumerate is True

    def test_enumerate_can_be_disabled(self):
        """Test that enumeration can be disabled."""
        config = FuzzerConfig(
            target_ip="127.0.0.1",
            target_port=8080,
            protocol="http",
            enumerate=False,
        )
        assert config.enumerate is False

    def test_protocol_options_methods(self):
        """Test methods can be specified via protocol_options."""
        config = FuzzerConfig(
            target_ip="127.0.0.1",
            target_port=8080,
            protocol="http",
            protocol_options={"methods": "GET,PUT,PROPFIND"},
        )
        assert config.get_option("methods") == "GET,PUT,PROPFIND"

    def test_protocol_options_webdav(self):
        """Test webdav can be specified via protocol_options."""
        config = FuzzerConfig(
            target_ip="127.0.0.1",
            target_port=8080,
            protocol="http",
            protocol_options={"webdav": False},
        )
        assert config.get_option("webdav") is False
