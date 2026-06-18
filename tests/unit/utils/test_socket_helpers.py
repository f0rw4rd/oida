#!/usr/bin/env python3
"""Tests for socket_helpers utility module (TLS helpers)."""

import ssl
import pytest
from unittest.mock import Mock, patch

from oida.utils.socket_helpers import (
    build_tls_context,
    check_tls_certificate,
)


@pytest.fixture
def mock_logger():
    """Create a mock logger for testing."""
    logger = Mock()
    logger.display = Mock()
    logger.fail = Mock()
    logger.debug = Mock()
    return logger


class TestBuildTLSContext:
    """Test build_tls_context helper."""

    def test_basic_context(self):
        """Test basic TLS context creation without client cert."""
        ctx = build_tls_context({})

        assert isinstance(ctx, ssl.SSLContext)
        assert ctx.check_hostname is False
        assert ctx.verify_mode == ssl.CERT_NONE

    def test_with_logger(self, mock_logger):
        """Test TLS context creation with logger."""
        ctx = build_tls_context({}, logger=mock_logger)

        assert isinstance(ctx, ssl.SSLContext)

    def test_with_client_cert_missing_file(self, mock_logger):
        """Test TLS context with non-existent client cert logs failure."""
        ctx = build_tls_context(
            {"tls-cert": "/nonexistent/cert.pem", "tls-key": "/nonexistent/key.pem"},
            logger=mock_logger,
        )

        assert isinstance(ctx, ssl.SSLContext)
        mock_logger.fail.assert_called_once()

    def test_empty_cert_key(self, mock_logger):
        """Test TLS context with empty cert/key values."""
        ctx = build_tls_context({"tls-cert": None, "tls-key": None}, logger=mock_logger)

        assert isinstance(ctx, ssl.SSLContext)
        mock_logger.fail.assert_not_called()


class TestCheckTLSCertificate:
    """Test check_tls_certificate helper."""

    @patch("oida.utils.socket_helpers.socket.create_connection")
    def test_connection_failure(self, mock_create_conn, mock_logger):
        """Test check_tls_certificate handles connection failure."""
        mock_create_conn.side_effect = ConnectionRefusedError("refused")

        result = check_tls_certificate("192.168.1.1", 443, mock_logger)

        assert result is None
        mock_logger.debug.assert_called()

    @patch("oida.utils.socket_helpers.socket.create_connection")
    def test_timeout(self, mock_create_conn, mock_logger):
        """Test check_tls_certificate handles timeout."""
        mock_create_conn.side_effect = TimeoutError("timeout")

        result = check_tls_certificate("192.168.1.1", 443, mock_logger, timeout=1)

        assert result is None

    def test_unreachable_host(self, mock_logger):
        """Test check_tls_certificate with unreachable host."""
        result = check_tls_certificate("192.0.2.1", 44399, mock_logger, timeout=1)

        assert result is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
