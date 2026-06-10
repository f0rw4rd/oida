#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for Modbus scanner connection methods.

Tests TCP, TLS, UDP, Serial, and RTU-over-TCP connection handling.
"""

import pytest
from unittest.mock import MagicMock, patch

# Check for pymodbus availability
try:
    import pymodbus

    PYMODBUS_AVAILABLE = True
except ImportError:
    PYMODBUS_AVAILABLE = False

pytestmark = pytest.mark.skipif(not PYMODBUS_AVAILABLE, reason="pymodbus library not installed")


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def mock_tcp_client():
    """Create a mock TCP client."""
    client = MagicMock()
    client.connect.return_value = True
    client.close.return_value = None
    return client


@pytest.fixture
def mock_tls_client():
    """Create a mock TLS client."""
    client = MagicMock()
    client.connect.return_value = True
    client.close.return_value = None
    client.socket = MagicMock()
    return client


@pytest.fixture
def mock_serial_client():
    """Create a mock serial client."""
    client = MagicMock()
    client.connect.return_value = True
    client.close.return_value = None
    return client


@pytest.fixture
def mock_udp_client():
    """Create a mock UDP client."""
    client = MagicMock()
    client.connect.return_value = True
    client.close.return_value = None
    return client


@pytest.fixture
def scanner_args():
    """Create default scanner arguments."""
    return {
        "rhost": "192.168.1.100",
        "rport": 502,
        "timeout": 5,
        "unit-id": 1,
        "scan-range": "0-100",
        "register-type": "all",
        "serial-port": "",
        "baudrate": 9600,
        "get-device-id": True,
        "transport": "tcp",
    }


def create_mock_scanner(args):
    """Create a mock ModbusScanner instance."""
    from oida.protocols.modbus.scanner import ModbusScanner

    with patch.object(ModbusScanner, "__init__", lambda self, *a, **kw: None):
        scanner = ModbusScanner.__new__(ModbusScanner)
        scanner.args = args
        scanner.host = args.get("rhost", "127.0.0.1")
        scanner.port = args.get("rport", 502)
        scanner.timeout = args.get("timeout", 5)
        scanner.serial_port = args.get("serial-port", "")
        scanner.baudrate = args.get("baudrate", 9600)
        scanner.logger = MagicMock()
        scanner.security = MagicMock()
        scanner.debug = False
        return scanner


# =============================================================================
# Test TCP Connection
# =============================================================================


class TestTCPConnection:
    """Tests for TCP connection handling."""

    @patch("oida.protocols.modbus.scanner._get_modbus_tcp_client")
    @patch("oida.protocols.modbus.scanner._get_modbus_serial_client")
    @patch("oida.protocols.modbus.scanner._get_modbus_tls_client")
    @patch("oida.protocols.modbus.scanner._get_modbus_udp_client")
    @patch("oida.protocols.modbus.scanner._get_framer_type")
    def test_tcp_connect_success(
        self,
        mock_framer,
        mock_udp,
        mock_tls,
        mock_serial,
        mock_tcp,
        scanner_args,
        mock_tcp_client,
    ):
        """Test successful TCP connection."""
        mock_tcp.return_value = MagicMock(return_value=mock_tcp_client)
        mock_framer.return_value = None
        mock_tls.return_value = None
        mock_udp.return_value = None

        scanner = create_mock_scanner(scanner_args)
        scanner.connect()

        # Connection should succeed
        mock_tcp_client.connect.assert_called_once()

    @patch("oida.protocols.modbus.scanner._get_modbus_tcp_client")
    @patch("oida.protocols.modbus.scanner._get_modbus_serial_client")
    @patch("oida.protocols.modbus.scanner._get_modbus_tls_client")
    @patch("oida.protocols.modbus.scanner._get_modbus_udp_client")
    @patch("oida.protocols.modbus.scanner._get_framer_type")
    def test_tcp_connect_failure(
        self,
        mock_framer,
        mock_udp,
        mock_tls,
        mock_serial,
        mock_tcp,
        scanner_args,
    ):
        """Test TCP connection failure."""
        failing_client = MagicMock()
        failing_client.connect.return_value = False
        mock_tcp.return_value = MagicMock(return_value=failing_client)
        mock_framer.return_value = None
        mock_tls.return_value = None
        mock_udp.return_value = None

        scanner = create_mock_scanner(scanner_args)
        result = scanner.connect()

        assert result is None

    @patch("oida.protocols.modbus.scanner._get_modbus_tcp_client")
    @patch("oida.protocols.modbus.scanner._get_modbus_serial_client")
    @patch("oida.protocols.modbus.scanner._get_modbus_tls_client")
    @patch("oida.protocols.modbus.scanner._get_modbus_udp_client")
    @patch("oida.protocols.modbus.scanner._get_framer_type")
    def test_tcp_connect_exception(
        self,
        mock_framer,
        mock_udp,
        mock_tls,
        mock_serial,
        mock_tcp,
        scanner_args,
    ):
        """Test TCP connection with exception."""
        failing_client = MagicMock()
        failing_client.connect.side_effect = Exception("Connection refused")
        mock_tcp.return_value = MagicMock(return_value=failing_client)
        mock_framer.return_value = None
        mock_tls.return_value = None
        mock_udp.return_value = None

        scanner = create_mock_scanner(scanner_args)
        result = scanner.connect()

        assert result is None


class TestDisconnect:
    """Tests for disconnect handling."""

    def test_disconnect_with_connection(self, scanner_args, mock_tcp_client):
        """Test disconnect with active connection."""
        scanner = create_mock_scanner(scanner_args)
        scanner.disconnect(mock_tcp_client)
        mock_tcp_client.close.assert_called_once()

    def test_disconnect_with_none(self, scanner_args):
        """Test disconnect with None connection."""
        scanner = create_mock_scanner(scanner_args)
        # Should not raise exception
        scanner.disconnect(None)


# =============================================================================
# Test TLS Connection
# =============================================================================


class TestTLSConnection:
    """Tests for TLS connection handling."""

    @patch("oida.protocols.modbus.scanner._get_modbus_tcp_client")
    @patch("oida.protocols.modbus.scanner._get_modbus_serial_client")
    @patch("oida.protocols.modbus.scanner._get_modbus_tls_client")
    @patch("oida.protocols.modbus.scanner._get_modbus_udp_client")
    @patch("oida.protocols.modbus.scanner._get_framer_type")
    def test_tls_connect_success(
        self,
        mock_framer,
        mock_udp,
        mock_tls,
        mock_serial,
        mock_tcp,
        scanner_args,
        mock_tls_client,
    ):
        """Test successful TLS connection."""
        scanner_args["tls"] = True
        mock_tls.return_value = MagicMock(return_value=mock_tls_client)
        mock_framer.return_value = None

        scanner = create_mock_scanner(scanner_args)
        scanner._check_tls_certificate = MagicMock()

        scanner.connect()

        mock_tls_client.connect.assert_called_once()

    @patch("oida.protocols.modbus.scanner._get_modbus_tcp_client")
    @patch("oida.protocols.modbus.scanner._get_modbus_serial_client")
    @patch("oida.protocols.modbus.scanner._get_modbus_tls_client")
    @patch("oida.protocols.modbus.scanner._get_modbus_udp_client")
    @patch("oida.protocols.modbus.scanner._get_framer_type")
    def test_tls_not_supported(
        self,
        mock_framer,
        mock_udp,
        mock_tls,
        mock_serial,
        mock_tcp,
        scanner_args,
    ):
        """Test TLS connection when TLS client not available."""
        scanner_args["tls"] = True
        mock_tls.return_value = None  # TLS not available
        mock_framer.return_value = None

        scanner = create_mock_scanner(scanner_args)
        result = scanner.connect()

        assert result is None
        scanner.logger.fail.assert_called()


class TestTLSCertificateCheck:
    """Tests for TLS certificate validation."""

    @patch("oida.utils.socket_helpers.check_tls_certificate")
    def test_check_tls_certificate_no_socket(self, mock_check_tls, scanner_args, mock_tls_client):
        """Test certificate check falls back to probe when socket not accessible."""
        mock_tls_client.socket = None
        mock_tls_client.transport = None
        mock_tls_client.params = None
        scanner = create_mock_scanner(scanner_args)
        scanner._check_tls_certificate(mock_tls_client)
        # Should fall back to central check_tls_certificate probe
        mock_check_tls.assert_called_once()

    @patch("oida.utils.security_findings.display_cert_info")
    def test_check_tls_certificate_with_cert(self, mock_display, scanner_args, mock_tls_client):
        """Test certificate check with valid certificate."""
        mock_socket = MagicMock()
        mock_socket.getpeercert.return_value = b"cert_data"
        mock_tls_client.socket = mock_socket

        scanner = create_mock_scanner(scanner_args)
        scanner._check_tls_certificate(mock_tls_client)
        mock_display.assert_called_once()

    @patch("oida.utils.security_findings.display_cert_info")
    def test_check_tls_certificate_with_issues(self, mock_display, scanner_args, mock_tls_client):
        """Test certificate check reporting issues."""
        mock_socket = MagicMock()
        mock_socket.getpeercert.return_value = b"cert_data"
        mock_tls_client.socket = mock_socket

        scanner = create_mock_scanner(scanner_args)
        mock_display.return_value = {"issues": ["Certificate expired", "Self-signed certificate"]}
        scanner._check_tls_certificate(mock_tls_client)

        mock_display.assert_called_once()


# =============================================================================
# Test Serial Connection
# =============================================================================


class TestSerialConnection:
    """Tests for serial/RTU connection handling."""

    @patch("oida.protocols.modbus.scanner._get_modbus_tcp_client")
    @patch("oida.protocols.modbus.scanner._get_modbus_serial_client")
    @patch("oida.protocols.modbus.scanner._get_modbus_tls_client")
    @patch("oida.protocols.modbus.scanner._get_modbus_udp_client")
    @patch("oida.protocols.modbus.scanner._get_framer_type")
    def test_serial_connect_success(
        self,
        mock_framer,
        mock_udp,
        mock_tls,
        mock_serial,
        mock_tcp,
        scanner_args,
        mock_serial_client,
    ):
        """Test successful serial connection."""
        scanner_args["serial-port"] = "/dev/ttyUSB0"
        mock_serial.return_value = MagicMock(return_value=mock_serial_client)
        mock_framer.return_value = None

        scanner = create_mock_scanner(scanner_args)
        scanner.connect()

        mock_serial_client.connect.assert_called_once()

    @patch("oida.protocols.modbus.scanner._get_modbus_tcp_client")
    @patch("oida.protocols.modbus.scanner._get_modbus_serial_client")
    @patch("oida.protocols.modbus.scanner._get_modbus_tls_client")
    @patch("oida.protocols.modbus.scanner._get_modbus_udp_client")
    @patch("oida.protocols.modbus.scanner._get_framer_type")
    def test_serial_connect_with_baudrate(
        self,
        mock_framer,
        mock_udp,
        mock_tls,
        mock_serial,
        mock_tcp,
        scanner_args,
        mock_serial_client,
    ):
        """Test serial connection with custom baudrate."""
        scanner_args["serial-port"] = "/dev/ttyUSB0"
        scanner_args["baudrate"] = 19200

        MockSerialClient = MagicMock(return_value=mock_serial_client)
        mock_serial.return_value = MockSerialClient
        mock_framer.return_value = None

        scanner = create_mock_scanner(scanner_args)
        scanner.connect()

        # Verify baudrate was passed
        call_kwargs = MockSerialClient.call_args[1]
        assert call_kwargs["baudrate"] == 19200

    @patch("oida.protocols.modbus.scanner._get_modbus_tcp_client")
    @patch("oida.protocols.modbus.scanner._get_modbus_serial_client")
    @patch("oida.protocols.modbus.scanner._get_modbus_tls_client")
    @patch("oida.protocols.modbus.scanner._get_modbus_udp_client")
    @patch("oida.protocols.modbus.scanner._get_framer_type")
    def test_serial_connect_with_parity(
        self,
        mock_framer,
        mock_udp,
        mock_tls,
        mock_serial,
        mock_tcp,
        scanner_args,
        mock_serial_client,
    ):
        """Test serial connection with parity setting."""
        scanner_args["serial-port"] = "/dev/ttyUSB0"
        scanner_args["parity"] = "E"

        MockSerialClient = MagicMock(return_value=mock_serial_client)
        mock_serial.return_value = MockSerialClient
        mock_framer.return_value = None

        scanner = create_mock_scanner(scanner_args)
        scanner.connect()

        call_kwargs = MockSerialClient.call_args[1]
        assert call_kwargs["parity"] == "E"

    @patch("oida.protocols.modbus.scanner._get_modbus_tcp_client")
    @patch("oida.protocols.modbus.scanner._get_modbus_serial_client")
    @patch("oida.protocols.modbus.scanner._get_modbus_tls_client")
    @patch("oida.protocols.modbus.scanner._get_modbus_udp_client")
    @patch("oida.protocols.modbus.scanner._get_framer_type")
    def test_serial_ascii_framing(
        self,
        mock_framer,
        mock_udp,
        mock_tls,
        mock_serial,
        mock_tcp,
        scanner_args,
        mock_serial_client,
    ):
        """Test serial connection with ASCII framing."""
        scanner_args["serial-port"] = "/dev/ttyUSB0"
        scanner_args["ascii"] = True

        MockSerialClient = MagicMock(return_value=mock_serial_client)
        mock_serial.return_value = MockSerialClient

        # Mock FramerType for pymodbus 3.x
        mock_framer_type = MagicMock()
        mock_framer_type.ASCII = "ascii_framer"
        mock_framer.return_value = mock_framer_type

        scanner = create_mock_scanner(scanner_args)
        scanner.connect()

        call_kwargs = MockSerialClient.call_args[1]
        assert "framer" in call_kwargs

    @patch("oida.protocols.modbus.scanner._get_modbus_tcp_client")
    @patch("oida.protocols.modbus.scanner._get_modbus_serial_client")
    @patch("oida.protocols.modbus.scanner._get_modbus_tls_client")
    @patch("oida.protocols.modbus.scanner._get_modbus_udp_client")
    @patch("oida.protocols.modbus.scanner._get_framer_type")
    def test_serial_connect_failure(
        self,
        mock_framer,
        mock_udp,
        mock_tls,
        mock_serial,
        mock_tcp,
        scanner_args,
    ):
        """Test serial connection failure."""
        scanner_args["serial-port"] = "/dev/ttyUSB0"
        mock_serial.return_value = MagicMock(side_effect=Exception("Port not found"))
        mock_framer.return_value = None

        scanner = create_mock_scanner(scanner_args)
        result = scanner.connect()

        assert result is None
        scanner.logger.fail.assert_called()


# =============================================================================
# Test UDP Connection
# =============================================================================


class TestUDPConnection:
    """Tests for UDP connection handling."""

    @patch("oida.protocols.modbus.scanner._get_modbus_tcp_client")
    @patch("oida.protocols.modbus.scanner._get_modbus_serial_client")
    @patch("oida.protocols.modbus.scanner._get_modbus_tls_client")
    @patch("oida.protocols.modbus.scanner._get_modbus_udp_client")
    @patch("oida.protocols.modbus.scanner._get_framer_type")
    def test_udp_connect_success(
        self,
        mock_framer,
        mock_udp,
        mock_tls,
        mock_serial,
        mock_tcp,
        scanner_args,
        mock_udp_client,
    ):
        """Test successful UDP connection."""
        scanner_args["udp"] = True
        mock_udp.return_value = MagicMock(return_value=mock_udp_client)
        mock_framer.return_value = None

        scanner = create_mock_scanner(scanner_args)
        scanner.connect()

        mock_udp_client.connect.assert_called_once()

    @patch("oida.protocols.modbus.scanner._get_modbus_tcp_client")
    @patch("oida.protocols.modbus.scanner._get_modbus_serial_client")
    @patch("oida.protocols.modbus.scanner._get_modbus_tls_client")
    @patch("oida.protocols.modbus.scanner._get_modbus_udp_client")
    @patch("oida.protocols.modbus.scanner._get_framer_type")
    def test_udp_not_supported(
        self,
        mock_framer,
        mock_udp,
        mock_tls,
        mock_serial,
        mock_tcp,
        scanner_args,
    ):
        """Test UDP connection when not available."""
        scanner_args["udp"] = True
        mock_udp.return_value = None  # UDP not available
        mock_framer.return_value = None

        scanner = create_mock_scanner(scanner_args)
        result = scanner.connect()

        assert result is None
        scanner.logger.fail.assert_called()


# =============================================================================
# Test RTU-over-TCP Connection
# =============================================================================


class TestRTUOverTCPConnection:
    """Tests for RTU-over-TCP connection handling."""

    @patch("oida.protocols.modbus.scanner._get_modbus_tcp_client")
    @patch("oida.protocols.modbus.scanner._get_modbus_serial_client")
    @patch("oida.protocols.modbus.scanner._get_modbus_tls_client")
    @patch("oida.protocols.modbus.scanner._get_modbus_udp_client")
    @patch("oida.protocols.modbus.scanner._get_framer_type")
    def test_rtu_over_tcp_connect(
        self,
        mock_framer,
        mock_udp,
        mock_tls,
        mock_serial,
        mock_tcp,
        scanner_args,
        mock_tcp_client,
    ):
        """Test RTU-over-TCP connection."""
        scanner_args["rtu-over-tcp"] = True

        MockTcpClient = MagicMock(return_value=mock_tcp_client)
        mock_tcp.return_value = MockTcpClient

        # Mock FramerType for pymodbus 3.x
        mock_framer_type = MagicMock()
        mock_framer_type.RTU = "rtu_framer"
        mock_framer.return_value = mock_framer_type

        mock_tls.return_value = None
        mock_udp.return_value = None

        scanner = create_mock_scanner(scanner_args)
        scanner.connect()

        # Verify RTU framer was used
        call_kwargs = MockTcpClient.call_args[1]
        assert call_kwargs.get("framer") == "rtu_framer"

    @patch("oida.protocols.modbus.scanner._get_modbus_tcp_client")
    @patch("oida.protocols.modbus.scanner._get_modbus_serial_client")
    @patch("oida.protocols.modbus.scanner._get_modbus_tls_client")
    @patch("oida.protocols.modbus.scanner._get_modbus_udp_client")
    @patch("oida.protocols.modbus.scanner._get_framer_type")
    def test_rtu_over_tcp_legacy_framer(
        self,
        mock_framer,
        mock_udp,
        mock_tls,
        mock_serial,
        mock_tcp,
        scanner_args,
        mock_tcp_client,
    ):
        """Test RTU-over-TCP with legacy framer string."""
        scanner_args["rtu-over-tcp"] = True

        MockTcpClient = MagicMock(return_value=mock_tcp_client)
        mock_tcp.return_value = MockTcpClient
        mock_framer.return_value = None  # No FramerType (older pymodbus)
        mock_tls.return_value = None
        mock_udp.return_value = None

        scanner = create_mock_scanner(scanner_args)
        scanner.connect()

        # Verify "rtu" string was used
        call_kwargs = MockTcpClient.call_args[1]
        assert call_kwargs.get("framer") == "rtu"


# =============================================================================
# Test ASCII-over-TCP Connection
# =============================================================================


class TestASCIIOverTCPConnection:
    """Tests for ASCII-over-TCP connection handling."""

    @patch("oida.protocols.modbus.scanner._get_modbus_tcp_client")
    @patch("oida.protocols.modbus.scanner._get_modbus_serial_client")
    @patch("oida.protocols.modbus.scanner._get_modbus_tls_client")
    @patch("oida.protocols.modbus.scanner._get_modbus_udp_client")
    @patch("oida.protocols.modbus.scanner._get_framer_type")
    def test_ascii_over_tcp_connect(
        self,
        mock_framer,
        mock_udp,
        mock_tls,
        mock_serial,
        mock_tcp,
        scanner_args,
        mock_tcp_client,
    ):
        """Test ASCII-over-TCP connection."""
        scanner_args["ascii-over-tcp"] = True

        MockTcpClient = MagicMock(return_value=mock_tcp_client)
        mock_tcp.return_value = MockTcpClient

        # Mock FramerType for pymodbus 3.x
        mock_framer_type = MagicMock()
        mock_framer_type.ASCII = "ascii_framer"
        mock_framer.return_value = mock_framer_type

        mock_tls.return_value = None
        mock_udp.return_value = None

        scanner = create_mock_scanner(scanner_args)
        scanner.connect()

        call_kwargs = MockTcpClient.call_args[1]
        assert call_kwargs.get("framer") == "ascii_framer"


# =============================================================================
# Test Transport Selection
# =============================================================================


class TestTransportSelection:
    """Tests for transport type selection logic."""

    def test_transport_tcp_default(self, scanner_args):
        """Test TCP is default transport."""
        scanner = create_mock_scanner(scanner_args)
        assert scanner.args.get("transport", "tcp") == "tcp"

    def test_transport_serial_by_port(self, scanner_args):
        """Test serial transport selected by serial-port arg."""
        scanner_args["serial-port"] = "/dev/ttyUSB0"
        scanner = create_mock_scanner(scanner_args)
        assert scanner.serial_port == "/dev/ttyUSB0"

    def test_transport_tls_by_flag(self, scanner_args):
        """Test TLS transport selected by tls flag."""
        scanner_args["tls"] = True
        scanner = create_mock_scanner(scanner_args)
        assert scanner.args.get("tls") is True

    def test_transport_udp_by_flag(self, scanner_args):
        """Test UDP transport selected by udp flag."""
        scanner_args["udp"] = True
        scanner = create_mock_scanner(scanner_args)
        assert scanner.args.get("udp") is True


# =============================================================================
# Test Flow Control Options
# =============================================================================


class TestFlowControlOptions:
    """Tests for serial flow control options."""

    @patch("oida.protocols.modbus.scanner._get_modbus_tcp_client")
    @patch("oida.protocols.modbus.scanner._get_modbus_serial_client")
    @patch("oida.protocols.modbus.scanner._get_modbus_tls_client")
    @patch("oida.protocols.modbus.scanner._get_modbus_udp_client")
    @patch("oida.protocols.modbus.scanner._get_framer_type")
    def test_rtscts_flow_control(
        self,
        mock_framer,
        mock_udp,
        mock_tls,
        mock_serial,
        mock_tcp,
        scanner_args,
        mock_serial_client,
    ):
        """Test RTS/CTS flow control option."""
        scanner_args["serial-port"] = "/dev/ttyUSB0"
        scanner_args["rtscts"] = True

        MockSerialClient = MagicMock(return_value=mock_serial_client)
        mock_serial.return_value = MockSerialClient
        mock_framer.return_value = None

        scanner = create_mock_scanner(scanner_args)
        scanner.connect()

        call_kwargs = MockSerialClient.call_args[1]
        # pymodbus 3.x ModbusSerialClient has no rtscts constructor kwarg
        # (passing it raised TypeError and broke serial entirely). Flow control
        # is applied to the underlying pyserial object instead.
        assert "rtscts" not in call_kwargs
        assert mock_serial_client.socket.rtscts is True

    @patch("oida.protocols.modbus.scanner._get_modbus_tcp_client")
    @patch("oida.protocols.modbus.scanner._get_modbus_serial_client")
    @patch("oida.protocols.modbus.scanner._get_modbus_tls_client")
    @patch("oida.protocols.modbus.scanner._get_modbus_udp_client")
    @patch("oida.protocols.modbus.scanner._get_framer_type")
    def test_dsrdtr_flow_control(
        self,
        mock_framer,
        mock_udp,
        mock_tls,
        mock_serial,
        mock_tcp,
        scanner_args,
        mock_serial_client,
    ):
        """Test DSR/DTR flow control option."""
        scanner_args["serial-port"] = "/dev/ttyUSB0"
        scanner_args["dsrdtr"] = True

        MockSerialClient = MagicMock(return_value=mock_serial_client)
        mock_serial.return_value = MockSerialClient
        mock_framer.return_value = None

        scanner = create_mock_scanner(scanner_args)
        scanner.connect()

        call_kwargs = MockSerialClient.call_args[1]
        # pymodbus 3.x ModbusSerialClient has no dsrdtr constructor kwarg;
        # flow control is applied to the underlying pyserial object instead.
        assert "dsrdtr" not in call_kwargs
        assert mock_serial_client.socket.dsrdtr is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
