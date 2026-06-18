"""
Tests for ProtocolAuthenticator classes.

Tests cover:
- ProtocolAuthenticator: abstract interface enforcement
- UsernamePasswordAuth: initialization, authenticate flow, validate, credentials
- MQTTAuthenticator: initialization, CONNECT packet building, authenticate, validate
- NoAuthenticator: always succeeds
"""

import pytest
from unittest.mock import Mock


# =============================================================================
# Test ProtocolAuthenticator Abstract Interface
# =============================================================================


class TestProtocolAuthenticatorInterface:
    """Tests for ProtocolAuthenticator abstract class."""

    def test_cannot_instantiate_directly(self):
        """ProtocolAuthenticator cannot be instantiated directly."""
        from src.oida.fuzz.core.auth import ProtocolAuthenticator

        with pytest.raises(TypeError):
            ProtocolAuthenticator()

    def test_subclass_must_implement_authenticate(self):
        """Subclass must implement authenticate."""
        from src.oida.fuzz.core.auth import ProtocolAuthenticator

        class IncompleteAuth(ProtocolAuthenticator):
            def validate(self, connection):
                return True

        with pytest.raises(TypeError):
            IncompleteAuth()

    def test_subclass_must_implement_validate(self):
        """Subclass must implement validate."""
        from src.oida.fuzz.core.auth import ProtocolAuthenticator

        class IncompleteAuth(ProtocolAuthenticator):
            def authenticate(self, connection):
                return True

        with pytest.raises(TypeError):
            IncompleteAuth()

    def test_get_credentials_default_empty(self):
        """Default get_credentials returns empty dict."""
        from src.oida.fuzz.core.auth import NoAuthenticator

        auth = NoAuthenticator()
        assert auth.get_credentials() == {}


# =============================================================================
# Test UsernamePasswordAuth
# =============================================================================


class TestUsernamePasswordAuthCreation:
    """Tests for UsernamePasswordAuth instantiation."""

    def test_basic_creation(self):
        """UsernamePasswordAuth can be created with basic params."""
        from src.oida.fuzz.core.auth import UsernamePasswordAuth

        auth = UsernamePasswordAuth("admin", "password123")
        assert auth.username == "admin"
        assert auth.password == "password123"

    def test_default_command_formats(self):
        """Default command formats use USER/PASS."""
        from src.oida.fuzz.core.auth import UsernamePasswordAuth

        auth = UsernamePasswordAuth("user", "pass")
        assert "USER" in auth.user_cmd_fmt
        assert "PASS" in auth.pass_cmd_fmt

    def test_default_response_codes(self):
        """Default response codes are 331 for USER and 230 for PASS."""
        from src.oida.fuzz.core.auth import UsernamePasswordAuth

        auth = UsernamePasswordAuth("user", "pass")
        assert 331 in auth.user_ok_codes
        assert 230 in auth.pass_ok_codes

    def test_custom_command_formats(self):
        """Custom command formats accepted."""
        from src.oida.fuzz.core.auth import UsernamePasswordAuth

        auth = UsernamePasswordAuth(
            "user", "pass", user_cmd_fmt="LOGIN {}\r\n", pass_cmd_fmt="SECRET {}\r\n"
        )
        assert auth.user_cmd_fmt == "LOGIN {}\r\n"
        assert auth.pass_cmd_fmt == "SECRET {}\r\n"


class TestUsernamePasswordAuthAuthenticate:
    """Tests for UsernamePasswordAuth authenticate method."""

    def test_successful_auth(self):
        """Successful authentication returns True."""
        from src.oida.fuzz.core.auth import UsernamePasswordAuth

        auth = UsernamePasswordAuth("admin", "pass123")

        conn = Mock()
        conn._send_command = Mock(return_value=(331, "User ok"))
        conn._send_command.side_effect = [
            (331, "User name okay, need password"),
            (230, "Login successful"),
        ]

        result = auth.authenticate(conn)
        assert result is True
        assert conn._send_command.call_count == 2

    def test_auth_connection_error(self):
        """Connection error during auth returns False."""
        from src.oida.fuzz.core.auth import UsernamePasswordAuth

        auth = UsernamePasswordAuth("admin", "pass")

        conn = Mock()
        conn._send_command.side_effect = ConnectionError("Connection refused")

        result = auth.authenticate(conn)
        assert result is False

    def test_auth_generic_error(self):
        """Generic error during auth returns False."""
        from src.oida.fuzz.core.auth import UsernamePasswordAuth

        auth = UsernamePasswordAuth("admin", "pass")

        conn = Mock()
        conn._send_command.side_effect = RuntimeError("Unexpected error")

        result = auth.authenticate(conn)
        assert result is False

    def test_validate_returns_true(self):
        """Default validate always returns True."""
        from src.oida.fuzz.core.auth import UsernamePasswordAuth

        auth = UsernamePasswordAuth("admin", "pass")
        assert auth.validate(Mock()) is True

    def test_get_credentials(self):
        """get_credentials returns username and password."""
        from src.oida.fuzz.core.auth import UsernamePasswordAuth

        auth = UsernamePasswordAuth("admin", "secret")
        creds = auth.get_credentials()
        assert creds["username"] == "admin"
        assert creds["password"] == "secret"


# =============================================================================
# Test MQTTAuthenticator
# =============================================================================


class TestMQTTAuthenticatorCreation:
    """Tests for MQTTAuthenticator instantiation."""

    def test_default_creation(self):
        """MQTTAuthenticator created with defaults."""
        from src.oida.fuzz.core.auth import MQTTAuthenticator

        auth = MQTTAuthenticator()
        assert auth.client_id == "oida-fuzz"
        assert auth.username is None
        assert auth.password is None
        assert auth.protocol_version == 4
        assert auth.keep_alive == 60
        assert auth.clean_session is True

    def test_custom_creation(self):
        """MQTTAuthenticator with custom parameters."""
        from src.oida.fuzz.core.auth import MQTTAuthenticator

        auth = MQTTAuthenticator(
            client_id="test-client",
            username="user",
            password="pass",
            protocol_version=5,
            keep_alive=120,
            clean_session=False,
        )
        assert auth.client_id == "test-client"
        assert auth.username == "user"
        assert auth.password == "pass"
        assert auth.protocol_version == 5
        assert auth.keep_alive == 120
        assert auth.clean_session is False


class TestMQTTAuthenticatorBuildPacket:
    """Tests for MQTT CONNECT packet building."""

    def test_basic_connect_packet(self):
        """Basic CONNECT packet structure."""
        from src.oida.fuzz.core.auth import MQTTAuthenticator

        auth = MQTTAuthenticator(client_id="test")
        packet = auth._build_connect_packet()

        # Packet type 0x10 (CONNECT)
        assert packet[0] == 0x10

        # Protocol name "MQTT" should be in packet
        assert b"MQTT" in packet

    def test_connect_packet_with_credentials(self):
        """CONNECT packet includes username and password."""
        from src.oida.fuzz.core.auth import MQTTAuthenticator

        auth = MQTTAuthenticator(client_id="test", username="admin", password="secret")
        packet = auth._build_connect_packet()
        assert b"admin" in packet
        assert b"secret" in packet

    def test_connect_packet_v3(self):
        """CONNECT packet for MQTT v3.1 uses MQIsdp."""
        from src.oida.fuzz.core.auth import MQTTAuthenticator

        auth = MQTTAuthenticator(protocol_version=3)
        packet = auth._build_connect_packet()
        assert b"MQIsdp" in packet

    def test_remaining_length_encoding_small(self):
        """Remaining length encoding for small values."""
        from src.oida.fuzz.core.auth import MQTTAuthenticator

        auth = MQTTAuthenticator()
        encoded = auth._encode_remaining_length(0)
        assert encoded == b"\x00"

    def test_remaining_length_encoding_medium(self):
        """Remaining length encoding for medium values."""
        from src.oida.fuzz.core.auth import MQTTAuthenticator

        auth = MQTTAuthenticator()
        encoded = auth._encode_remaining_length(127)
        assert encoded == b"\x7f"

    def test_remaining_length_encoding_multi_byte(self):
        """Remaining length encoding for multi-byte values."""
        from src.oida.fuzz.core.auth import MQTTAuthenticator

        auth = MQTTAuthenticator()
        encoded = auth._encode_remaining_length(128)
        assert encoded == b"\x80\x01"


class TestMQTTAuthenticatorAuthenticate:
    """Tests for MQTT authenticate method."""

    def test_successful_connack(self):
        """Successful CONNACK returns True."""
        from src.oida.fuzz.core.auth import MQTTAuthenticator

        auth = MQTTAuthenticator()
        conn = Mock()
        # CONNACK: type=0x20, remaining_length=2, session_present=0, return_code=0
        conn.recv.return_value = b"\x20\x02\x00\x00"
        result = auth.authenticate(conn)
        assert result is True

    def test_bad_credentials_connack(self):
        """CONNACK with bad credentials returns False."""
        from src.oida.fuzz.core.auth import MQTTAuthenticator

        auth = MQTTAuthenticator()
        conn = Mock()
        # Return code 0x04 = bad username or password
        conn.recv.return_value = b"\x20\x02\x00\x04"
        result = auth.authenticate(conn)
        assert result is False

    def test_wrong_packet_type(self):
        """Non-CONNACK response returns False."""
        from src.oida.fuzz.core.auth import MQTTAuthenticator

        auth = MQTTAuthenticator()
        conn = Mock()
        conn.recv.return_value = b"\x30\x02\x00\x00"  # PUBLISH, not CONNACK
        result = auth.authenticate(conn)
        assert result is False

    def test_incomplete_connack(self):
        """Incomplete CONNACK returns False."""
        from src.oida.fuzz.core.auth import MQTTAuthenticator

        auth = MQTTAuthenticator()
        conn = Mock()
        conn.recv.return_value = b"\x20\x02"  # Only 2 bytes
        result = auth.authenticate(conn)
        assert result is False

    def test_connection_error(self):
        """Connection error during auth returns False."""
        from src.oida.fuzz.core.auth import MQTTAuthenticator

        auth = MQTTAuthenticator()
        conn = Mock()
        conn.send.side_effect = ConnectionError("Refused")
        result = auth.authenticate(conn)
        assert result is False


class TestMQTTAuthenticatorValidate:
    """Tests for MQTT validate (PINGREQ/PINGRESP)."""

    def test_successful_pingresp(self):
        """Successful PINGRESP returns True."""
        from src.oida.fuzz.core.auth import MQTTAuthenticator

        auth = MQTTAuthenticator()
        conn = Mock()
        conn.recv.return_value = b"\xd0\x00"
        result = auth.validate(conn)
        assert result is True

    def test_invalid_pingresp(self):
        """Invalid PINGRESP returns False."""
        from src.oida.fuzz.core.auth import MQTTAuthenticator

        auth = MQTTAuthenticator()
        conn = Mock()
        conn.recv.return_value = b"\xff\x00"
        result = auth.validate(conn)
        assert result is False

    def test_validate_connection_error(self):
        """Connection error during validate returns False."""
        from src.oida.fuzz.core.auth import MQTTAuthenticator

        auth = MQTTAuthenticator()
        conn = Mock()
        conn.send.side_effect = Exception("Connection lost")
        result = auth.validate(conn)
        assert result is False


class TestMQTTAuthenticatorCredentials:
    """Tests for MQTT get_credentials."""

    def test_credentials_with_username(self):
        """Credentials with username present."""
        from src.oida.fuzz.core.auth import MQTTAuthenticator

        auth = MQTTAuthenticator(client_id="test", username="user", password="pass")
        creds = auth.get_credentials()
        assert creds["client_id"] == "test"
        assert creds["username"] == "user"
        assert creds["password"] == "***"  # Masked

    def test_credentials_without_username(self):
        """Credentials without username."""
        from src.oida.fuzz.core.auth import MQTTAuthenticator

        auth = MQTTAuthenticator(client_id="test")
        creds = auth.get_credentials()
        assert creds["username"] == "(none)"
        assert creds["password"] == "(none)"


# =============================================================================
# Test NoAuthenticator
# =============================================================================


class TestNoAuthenticator:
    """Tests for NoAuthenticator."""

    def test_authenticate_always_true(self):
        """NoAuthenticator always returns True for authenticate."""
        from src.oida.fuzz.core.auth import NoAuthenticator

        auth = NoAuthenticator()
        assert auth.authenticate(Mock()) is True

    def test_validate_always_true(self):
        """NoAuthenticator always returns True for validate."""
        from src.oida.fuzz.core.auth import NoAuthenticator

        auth = NoAuthenticator()
        assert auth.validate(Mock()) is True

    def test_get_credentials_empty(self):
        """NoAuthenticator returns empty credentials."""
        from src.oida.fuzz.core.auth import NoAuthenticator

        auth = NoAuthenticator()
        assert auth.get_credentials() == {}
