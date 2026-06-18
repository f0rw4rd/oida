"""
Tests for StatefulConnection, TLSHandler, and BannerConnection.

Tests cover:
- StatefulConnection: abstract interface enforcement
- StatefulConnection: initialization parameters
- StatefulConnection: close resets handshake state
- StatefulConnection: _parse_response_code
- TLSHandler: initialization, get_tls_info, create_default_context
- BannerConnection: creation and handshake behavior
"""

import pytest
import ssl
from unittest.mock import MagicMock


# =============================================================================
# Test StatefulConnection Abstract Interface
# =============================================================================


class TestStatefulConnectionInterface:
    """Tests for StatefulConnection abstract requirements."""

    def test_cannot_instantiate_directly(self):
        """StatefulConnection requires _perform_handshake to be implemented."""
        from src.oida.fuzz.core.connections.stateful import StatefulConnection

        with pytest.raises(TypeError):
            StatefulConnection("127.0.0.1", 21)

    def test_concrete_subclass_accepted(self):
        """Concrete subclass with _perform_handshake can be instantiated."""
        from src.oida.fuzz.core.connections.stateful import StatefulConnection

        class ConcreteConn(StatefulConnection):
            def _perform_handshake(self):
                pass

        conn = ConcreteConn("127.0.0.1", 21, protocol_name="TEST")
        assert conn.handshake_complete is False
        assert conn.server_info == {}
        assert conn._protocol_name == "TEST"


class TestStatefulConnectionInit:
    """Tests for StatefulConnection initialization."""

    def _make_concrete(self, *args, **kwargs):
        """Create a concrete StatefulConnection for testing."""
        from src.oida.fuzz.core.connections.stateful import StatefulConnection

        class TestConn(StatefulConnection):
            def _perform_handshake(self):
                pass

        return TestConn(*args, **kwargs)

    def test_default_parameters(self):
        """Default parameters are set correctly."""
        conn = self._make_concrete("10.0.0.1", 502)
        assert conn.handshake_complete is False
        assert conn.max_retries == 3
        assert conn.retry_delay == 1.0
        assert conn._consecutive_failures == 0
        assert conn._connection_generation == 0

    def test_custom_parameters(self):
        """Custom parameters are accepted."""
        conn = self._make_concrete(
            "10.0.0.1",
            502,
            send_timeout=10.0,
            recv_timeout=15.0,
            protocol_name="MODBUS",
            max_retries=5,
            retry_delay=2.0,
        )
        assert conn.max_retries == 5
        assert conn.retry_delay == 2.0
        assert conn._protocol_name == "MODBUS"


class TestStatefulConnectionParseResponseCode:
    """Tests for _parse_response_code."""

    def _make_concrete(self, *args, **kwargs):
        from src.oida.fuzz.core.connections.stateful import StatefulConnection

        class TestConn(StatefulConnection):
            def _perform_handshake(self):
                pass

        return TestConn(*args, **kwargs)

    def test_standard_3_digit_code(self):
        """Parse standard 3-digit response code."""
        conn = self._make_concrete("127.0.0.1", 21)
        assert conn._parse_response_code("220 FTP ready") == 220
        assert conn._parse_response_code("331 User ok") == 331
        assert conn._parse_response_code("230 Login successful") == 230
        assert conn._parse_response_code("550 Permission denied") == 550

    def test_invalid_code_returns_minus_1(self):
        """Non-numeric first 3 chars returns -1."""
        conn = self._make_concrete("127.0.0.1", 21)
        assert conn._parse_response_code("XYZ Invalid") == -1

    def test_empty_string_returns_minus_1(self):
        """Empty string returns -1."""
        conn = self._make_concrete("127.0.0.1", 21)
        assert conn._parse_response_code("") == -1


class TestStatefulConnectionClose:
    """Tests for close() behavior."""

    def test_close_resets_state(self):
        """close() resets handshake_complete and server_info."""
        from src.oida.fuzz.core.connections.stateful import StatefulConnection

        class TestConn(StatefulConnection):
            def _perform_handshake(self):
                pass

        conn = TestConn("127.0.0.1", 21, protocol_name="TEST")
        conn.handshake_complete = True
        conn.server_info = {"banner": "FTP ready"}

        # Create a mock socket so close doesn't fail
        conn._sock = MagicMock()

        conn.close()
        assert conn.handshake_complete is False
        assert conn.server_info == {}


# =============================================================================
# Test TLSHandler
# =============================================================================


class TestTLSHandler:
    """Tests for TLSHandler."""

    def test_default_creation(self):
        """TLSHandler created with defaults."""
        from src.oida.fuzz.core.connections.stateful import TLSHandler

        handler = TLSHandler()
        assert handler.sslcontext is None
        assert handler.is_secure is False

    def test_creation_with_context(self):
        """TLSHandler with explicit SSL context."""
        from src.oida.fuzz.core.connections.stateful import TLSHandler

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        handler = TLSHandler(sslcontext=ctx)
        assert handler.sslcontext is ctx

    def test_get_tls_info_not_secure(self):
        """get_tls_info returns not secure when not upgraded."""
        from src.oida.fuzz.core.connections.stateful import TLSHandler

        handler = TLSHandler()
        info = handler.get_tls_info()
        assert info == {"secure": False}

    def test_get_tls_info_secure(self):
        """get_tls_info returns secure info after upgrade."""
        from src.oida.fuzz.core.connections.stateful import TLSHandler

        handler = TLSHandler()
        handler.is_secure = True
        handler._tls_info = {
            "version": "TLSv1.3",
            "cipher_suite": "TLS_AES_256_GCM_SHA384",
            "cipher_bits": 256,
        }
        info = handler.get_tls_info()
        assert info["secure"] is True
        assert info["version"] == "TLSv1.3"
        assert info["cipher_suite"] == "TLS_AES_256_GCM_SHA384"

    def test_create_default_context_is_permissive(self):
        """Default context is permissive for testing."""
        from src.oida.fuzz.core.connections.stateful import TLSHandler

        handler = TLSHandler()
        ctx = handler._create_default_context()
        assert ctx.check_hostname is False
        assert ctx.verify_mode == ssl.CERT_NONE


# =============================================================================
# Test TLSUpgradeMixin
# =============================================================================


class TestTLSUpgradeMixin:
    """Tests for TLSUpgradeMixin (deprecated but still in use)."""

    def test_init_defaults(self):
        """TLSUpgradeMixin initializes with defaults."""
        from src.oida.fuzz.core.connections.stateful import TLSUpgradeMixin

        mixin = TLSUpgradeMixin.__new__(TLSUpgradeMixin)
        TLSUpgradeMixin.__init__(mixin)
        assert mixin.sslcontext is None
        assert mixin.is_secure is False

    def test_get_tls_info_not_secure(self):
        """_get_tls_info returns not secure when not upgraded."""
        from src.oida.fuzz.core.connections.stateful import TLSUpgradeMixin

        mixin = TLSUpgradeMixin.__new__(TLSUpgradeMixin)
        TLSUpgradeMixin.__init__(mixin)
        info = mixin._get_tls_info()
        assert info == {"secure": False}


# =============================================================================
# Test BannerConnection
# =============================================================================


class TestBannerConnection:
    """Tests for BannerConnection."""

    def test_creation(self):
        """BannerConnection can be created."""
        from src.oida.fuzz.core.connections.stateful import BannerConnection

        conn = BannerConnection("127.0.0.1", 21, expected_prefix=b"220", protocol_name="FTP")
        assert conn._expected_prefix == b"220"

    def test_creation_without_prefix(self):
        """BannerConnection can be created without expected prefix."""
        from src.oida.fuzz.core.connections.stateful import BannerConnection

        conn = BannerConnection("127.0.0.1", 25, protocol_name="SMTP")
        assert conn._expected_prefix is None

    def test_handshake_consumes_banner(self):
        """_perform_handshake consumes banner and stores in server_info."""
        from src.oida.fuzz.core.connections.stateful import BannerConnection

        conn = BannerConnection("127.0.0.1", 21, expected_prefix=b"220")

        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"220 FTP Server Ready\r\n"
        mock_sock.gettimeout.return_value = 5.0
        conn._sock = mock_sock

        conn._perform_handshake()
        assert "FTP Server Ready" in conn.server_info["banner"]

    def test_handshake_with_wrong_prefix_raises(self):
        """_perform_handshake raises on wrong banner prefix."""
        from src.oida.fuzz.core.connections.stateful import BannerConnection

        conn = BannerConnection("127.0.0.1", 21, expected_prefix=b"220")

        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"421 Service not available\r\n"
        mock_sock.gettimeout.return_value = 5.0
        conn._sock = mock_sock

        with pytest.raises(ConnectionError, match="Unexpected banner"):
            conn._perform_handshake()
