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

    def test_ca_insecure_skips_verification(self, mock_logger):
        """--tls-insecure overrides --tls-ca: verification stays disabled."""
        ctx = build_tls_context(
            {"tls-ca": "/nonexistent/ca.pem", "tls-insecure": True},
            logger=mock_logger,
        )

        assert ctx.verify_mode == ssl.CERT_NONE
        # CA load is skipped entirely, so no failure is logged for the bad path.
        mock_logger.fail.assert_not_called()

    def test_ca_missing_file_logs_failure(self, mock_logger):
        """A --tls-ca pointing at a missing file logs a failure and stays insecure."""
        ctx = build_tls_context({"tls-ca": "/nonexistent/ca.pem"}, logger=mock_logger)

        assert ctx.verify_mode == ssl.CERT_NONE
        mock_logger.fail.assert_called_once()

    def test_ca_enables_server_verification(self, tmp_path, mock_logger):
        """A valid --tls-ca bundle switches the context to CERT_REQUIRED (mTLS server check)."""
        pytest.importorskip("cryptography")
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        import datetime

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "oida-test-ca")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime(2020, 1, 1))
            .not_valid_after(datetime.datetime(2040, 1, 1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256())
        )
        ca_file = tmp_path / "ca.pem"
        ca_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

        ctx = build_tls_context({"tls-ca": str(ca_file)}, logger=mock_logger)

        assert ctx.verify_mode == ssl.CERT_REQUIRED
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
