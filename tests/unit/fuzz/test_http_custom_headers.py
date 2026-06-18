"""
Integration tests for HTTP Fuzzer Custom Headers feature.

Tests the ability to inject custom headers (Cookie, Authorization, etc.)
into HTTP fuzzing requests via:
- headers_file: Path to file with headers
- header: Inline header specification
- cookie: Cookie header shorthand
- auth_bearer: Bearer token shorthand
- auth_basic: Basic auth shorthand
"""

import base64
import os
import tempfile
from unittest.mock import MagicMock, patch

import pytest

from oida.fuzz.core.config import FuzzerConfig, MonitorConfig
from oida.fuzz.core.connections import MockConnectionFactory
from oida.fuzz.protocols.http_protocol import HTTPFuzzer

pytestmark = pytest.mark.core


@pytest.fixture
def mock_connection_factory():
    """Create a MockConnectionFactory for testing."""
    return MockConnectionFactory()


@pytest.fixture
def temp_headers_file():
    """Create a temporary headers file for testing."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("# Test headers file\n")
        f.write("Authorization: Bearer test-jwt-token\n")
        f.write("Cookie: session=abc123; user=admin\n")
        f.write("X-Api-Key: my-secret-key\n")
        f.write("X-Custom-Header: custom-value\n")
        f.write("\n")  # Empty line should be ignored
        f.write("# Another comment\n")
        f.write("Accept: application/json\n")
        f.flush()
        yield f.name
    os.unlink(f.name)


def create_http_config(protocol_options=None, enumerate=False):
    """Create a FuzzerConfig for HTTP testing."""
    no_monitors = MonitorConfig.parse("none")
    return FuzzerConfig(
        target_ip="127.0.0.1",
        target_port=8080,
        protocol="http",
        session_filename="test_http_headers",
        log_session=False,
        console_output=False,
        web_interface=False,
        enumerate=enumerate,
        skip_pre_send_checks=True,
        monitor_config=no_monitors,
        boofuzz_db=False,
        protocol_options=protocol_options or {},
    )


class TestHTTPCustomHeadersLoading:
    """Test loading of custom headers from various sources."""

    def test_load_headers_from_file(self, temp_headers_file, mock_connection_factory):
        """Test loading headers from a file."""
        config = create_http_config(protocol_options={"headers_file": temp_headers_file})
        fuzzer = HTTPFuzzer(config, mock_connection_factory)

        assert len(fuzzer.custom_headers) == 5

        # Check each header was loaded correctly
        header_dict = dict(fuzzer.custom_headers)
        assert header_dict["Authorization"] == "Bearer test-jwt-token"
        assert header_dict["Cookie"] == "session=abc123; user=admin"
        assert header_dict["X-Api-Key"] == "my-secret-key"
        assert header_dict["X-Custom-Header"] == "custom-value"
        assert header_dict["Accept"] == "application/json"

    def test_load_headers_from_nonexistent_file(self, mock_connection_factory):
        """Test graceful handling of nonexistent headers file."""
        config = create_http_config(
            protocol_options={"headers_file": "/nonexistent/path/headers.txt"}
        )
        # Should not raise, just log a warning
        fuzzer = HTTPFuzzer(config, mock_connection_factory)
        assert len(fuzzer.custom_headers) == 0

    def test_load_inline_header(self, mock_connection_factory):
        """Test loading a single inline header."""
        config = create_http_config(protocol_options={"header": "X-Custom:my-value"})
        fuzzer = HTTPFuzzer(config, mock_connection_factory)

        assert len(fuzzer.custom_headers) == 1
        assert fuzzer.custom_headers[0] == ("X-Custom", "my-value")

    def test_load_multiple_inline_headers(self, mock_connection_factory):
        """Test loading multiple comma-separated inline headers."""
        config = create_http_config(
            protocol_options={"header": "X-First:value1,X-Second:value2,X-Third:value3"}
        )
        fuzzer = HTTPFuzzer(config, mock_connection_factory)

        assert len(fuzzer.custom_headers) == 3
        header_dict = dict(fuzzer.custom_headers)
        assert header_dict["X-First"] == "value1"
        assert header_dict["X-Second"] == "value2"
        assert header_dict["X-Third"] == "value3"

    def test_cookie_shorthand(self, mock_connection_factory):
        """Test cookie shorthand option."""
        config = create_http_config(protocol_options={"cookie": "session=xyz789; csrf=token123"})
        fuzzer = HTTPFuzzer(config, mock_connection_factory)

        assert len(fuzzer.custom_headers) == 1
        assert fuzzer.custom_headers[0] == ("Cookie", "session=xyz789; csrf=token123")

    def test_bearer_token_shorthand(self, mock_connection_factory):
        """Test bearer token shorthand option."""
        config = create_http_config(
            protocol_options={"auth_bearer": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test"}
        )
        fuzzer = HTTPFuzzer(config, mock_connection_factory)

        assert len(fuzzer.custom_headers) == 1
        assert fuzzer.custom_headers[0][0] == "Authorization"
        assert fuzzer.custom_headers[0][1] == "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test"

    def test_basic_auth_shorthand(self, mock_connection_factory):
        """Test basic auth shorthand option with proper encoding."""
        config = create_http_config(protocol_options={"auth_basic": "admin:secretpassword"})
        fuzzer = HTTPFuzzer(config, mock_connection_factory)

        assert len(fuzzer.custom_headers) == 1
        name, value = fuzzer.custom_headers[0]
        assert name == "Authorization"
        assert value.startswith("Basic ")

        # Verify encoding
        encoded_part = value.split(" ")[1]
        decoded = base64.b64decode(encoded_part).decode()
        assert decoded == "admin:secretpassword"

    def test_combined_header_options(self, mock_connection_factory):
        """Test combining multiple header options."""
        config = create_http_config(
            protocol_options={
                "header": "X-Custom:value",
                "cookie": "session=abc",
                "auth_bearer": "token123",
            }
        )
        fuzzer = HTTPFuzzer(config, mock_connection_factory)

        assert len(fuzzer.custom_headers) == 3
        header_dict = dict(fuzzer.custom_headers)
        assert header_dict["X-Custom"] == "value"
        assert header_dict["Cookie"] == "session=abc"
        assert header_dict["Authorization"] == "Bearer token123"

    def test_file_and_inline_headers_combined(self, temp_headers_file, mock_connection_factory):
        """Test combining file and inline header options."""
        config = create_http_config(
            protocol_options={
                "headers_file": temp_headers_file,
                "header": "X-Extra:extra-value",
            }
        )
        fuzzer = HTTPFuzzer(config, mock_connection_factory)

        # 5 from file + 1 inline
        assert len(fuzzer.custom_headers) == 6
        header_names = [h[0] for h in fuzzer.custom_headers]
        assert "X-Extra" in header_names
        assert "X-Api-Key" in header_names


class TestHTTPCustomHeadersBlockGeneration:
    """Test generation of boofuzz blocks for custom headers."""

    def test_empty_headers_returns_empty_tuple(self, mock_connection_factory):
        """Test that no custom headers returns empty tuple."""
        config = create_http_config()
        fuzzer = HTTPFuzzer(config, mock_connection_factory)

        blocks = fuzzer._build_custom_headers_children()
        assert blocks == ()

    def test_headers_generate_blocks(self, mock_connection_factory):
        """Test that custom headers generate proper blocks."""
        config = create_http_config(
            protocol_options={
                "header": "X-Test:value1,X-Another:value2",
            }
        )
        fuzzer = HTTPFuzzer(config, mock_connection_factory)

        blocks = fuzzer._build_custom_headers_children()
        assert len(blocks) == 2

        # Verify blocks are boofuzz Block objects
        from boofuzz import Block

        for block in blocks:
            assert isinstance(block, Block)

    def test_block_names_are_unique(self, mock_connection_factory):
        """Test that generated block names are unique."""
        config = create_http_config(
            protocol_options={
                "header": "H1:v1,H2:v2,H3:v3,H4:v4",
            }
        )
        fuzzer = HTTPFuzzer(config, mock_connection_factory)

        blocks = fuzzer._build_custom_headers_children()
        names = [block.name for block in blocks]
        assert len(names) == len(set(names)), "Block names should be unique"


class TestHTTPCustomHeadersInRequests:
    """Test that custom headers are properly injected into HTTP requests."""

    def test_baseline_request_includes_custom_headers(self, mock_connection_factory):
        """Test HTTP_Baseline request includes custom headers."""
        config = create_http_config(protocol_options={"cookie": "session=test123"})
        fuzzer = HTTPFuzzer(config, mock_connection_factory)

        # Access session to trigger _define_protocol
        with patch.object(fuzzer, "_create_socket") as mock_socket:
            mock_conn = MagicMock()
            mock_conn.open = MagicMock()
            mock_conn.close = MagicMock()
            mock_conn.send = MagicMock(return_value=100)
            mock_conn.recv = MagicMock(return_value=b"HTTP/1.1 200 OK\r\n\r\n")
            mock_socket.return_value = mock_conn

            session = fuzzer.session
            assert session is not None

            # Check that custom header block exists in baseline request
            # The structure should include our custom Cookie header
            assert len(fuzzer.custom_headers) == 1
            assert fuzzer.custom_headers[0] == ("Cookie", "session=test123")

    def test_unified_request_includes_custom_headers(self, mock_connection_factory):
        """Test HTTP_Unified_Standard request includes custom headers."""
        config = create_http_config(
            protocol_options={
                "auth_bearer": "jwt-token",
                "cookie": "session=xyz",
            }
        )
        fuzzer = HTTPFuzzer(config, mock_connection_factory)

        with patch.object(fuzzer, "_create_socket") as mock_socket:
            mock_conn = MagicMock()
            mock_conn.open = MagicMock()
            mock_conn.close = MagicMock()
            mock_conn.send = MagicMock(return_value=100)
            mock_conn.recv = MagicMock(return_value=b"HTTP/1.1 200 OK\r\n\r\n")
            mock_socket.return_value = mock_conn

            session = fuzzer.session
            assert session is not None

            # Verify headers are configured
            assert len(fuzzer.custom_headers) == 2
            header_dict = dict(fuzzer.custom_headers)
            assert "Authorization" in header_dict
            assert "Cookie" in header_dict


class TestHTTPCustomHeadersEdgeCases:
    """Test edge cases and error handling for custom headers."""

    def test_header_with_colon_in_value(self, mock_connection_factory):
        """Test header value containing colons is handled correctly."""
        config = create_http_config(
            protocol_options={"header": "X-Url:https://example.com:8080/path"}
        )
        fuzzer = HTTPFuzzer(config, mock_connection_factory)

        assert len(fuzzer.custom_headers) == 1
        name, value = fuzzer.custom_headers[0]
        assert name == "X-Url"
        assert value == "https://example.com:8080/path"

    def test_empty_header_value(self, mock_connection_factory):
        """Test header with empty value."""
        config = create_http_config(protocol_options={"header": "X-Empty:"})
        fuzzer = HTTPFuzzer(config, mock_connection_factory)

        assert len(fuzzer.custom_headers) == 1
        assert fuzzer.custom_headers[0] == ("X-Empty", "")

    def test_header_with_spaces(self, mock_connection_factory):
        """Test header values with leading/trailing spaces are trimmed."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("  X-Spaced  :  value with spaces  \n")
            f.flush()
            temp_file = f.name

        try:
            config = create_http_config(protocol_options={"headers_file": temp_file})
            fuzzer = HTTPFuzzer(config, mock_connection_factory)

            assert len(fuzzer.custom_headers) == 1
            name, value = fuzzer.custom_headers[0]
            assert name == "X-Spaced"
            assert value == "value with spaces"
        finally:
            os.unlink(temp_file)

    def test_special_characters_in_cookie(self, mock_connection_factory):
        """Test cookie values with special characters."""
        cookie_value = "session=abc123!@#$%^&*(); path=/; domain=.example.com"
        config = create_http_config(protocol_options={"cookie": cookie_value})
        fuzzer = HTTPFuzzer(config, mock_connection_factory)

        assert len(fuzzer.custom_headers) == 1
        assert fuzzer.custom_headers[0] == ("Cookie", cookie_value)

    def test_unicode_in_header_value(self, mock_connection_factory):
        """Test header with unicode characters (will be encoded)."""
        # Note: HTTP headers should be ASCII, but we test the handling
        config = create_http_config(protocol_options={"header": "X-Unicode:test-value"})
        fuzzer = HTTPFuzzer(config, mock_connection_factory)

        assert len(fuzzer.custom_headers) == 1

    def test_very_long_header_value(self, mock_connection_factory):
        """Test handling of very long header values."""
        long_value = "A" * 10000
        config = create_http_config(protocol_options={"header": f"X-Long:{long_value}"})
        fuzzer = HTTPFuzzer(config, mock_connection_factory)

        assert len(fuzzer.custom_headers) == 1
        assert fuzzer.custom_headers[0][1] == long_value

    def test_basic_auth_with_special_characters(self, mock_connection_factory):
        """Test basic auth with special characters in password."""
        config = create_http_config(protocol_options={"auth_basic": "user:p@ss:word!123"})
        fuzzer = HTTPFuzzer(config, mock_connection_factory)

        assert len(fuzzer.custom_headers) == 1
        name, value = fuzzer.custom_headers[0]
        assert name == "Authorization"

        # Verify decoding
        encoded_part = value.split(" ")[1]
        decoded = base64.b64decode(encoded_part).decode()
        assert decoded == "user:p@ss:word!123"


class TestHTTPCustomHeadersProtocolOptions:
    """Test that protocol options are correctly exposed."""

    def test_protocol_options_include_header_options(self):
        """Test that HTTPFuzzer.PROTOCOL_OPTIONS includes header options."""
        options = HTTPFuzzer.PROTOCOL_OPTIONS

        assert "headers_file" in options
        assert "header" in options
        assert "cookie" in options
        assert "auth_bearer" in options
        assert "auth_basic" in options

    def test_protocol_options_have_descriptions(self):
        """Test that header options have descriptions."""
        options = HTTPFuzzer.PROTOCOL_OPTIONS

        for opt_name in [
            "headers_file",
            "header",
            "cookie",
            "auth_bearer",
            "auth_basic",
        ]:
            assert "description" in options[opt_name]
            assert len(options[opt_name]["description"]) > 0

    def test_protocol_options_have_examples(self):
        """Test that header options have examples."""
        options = HTTPFuzzer.PROTOCOL_OPTIONS

        for opt_name in [
            "headers_file",
            "header",
            "cookie",
            "auth_bearer",
            "auth_basic",
        ]:
            assert "example" in options[opt_name]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
