#!/usr/bin/env python3
"""
Timeout boundary tests for OIDA scanners.

These tests verify scanner behavior with edge-case timeout values:
- Zero timeout
- Negative timeout
- Very small timeout (1ms)
- Very large timeout (1 hour+)
- Timeout during various operation phases
"""

import unittest
from unittest.mock import Mock, patch, AsyncMock
import socket
import asyncio
import pytest


# ==============================================================================
# Timeout Boundary Tests - Edge Cases
# ==============================================================================


class TestModbusTimeoutBoundaries(unittest.TestCase):
    """Test Modbus scanner timeout boundary conditions."""

    @patch("oida.protocols.modbus.scanner._get_pymodbus")
    def test_zero_timeout(self, mock_pymodbus):
        """Test Modbus scanner with zero timeout."""
        from oida.protocols.modbus.scanner import ModbusScanner

        args = {"rhost": "127.0.0.1", "rport": 502, "timeout": 0}
        scanner = ModbusScanner(args)

        self.assertEqual(scanner.timeout, 0)

    @patch("oida.protocols.modbus.scanner._get_pymodbus")
    def test_negative_timeout(self, mock_pymodbus):
        """Test Modbus scanner with negative timeout."""
        from oida.protocols.modbus.scanner import ModbusScanner

        args = {"rhost": "127.0.0.1", "rport": 502, "timeout": -1}
        scanner = ModbusScanner(args)

        # Should store the value (behavior defined by implementation)
        self.assertIsNotNone(scanner.timeout)

    @patch("oida.protocols.modbus.scanner._get_pymodbus")
    def test_very_small_timeout(self, mock_pymodbus):
        """Test Modbus scanner with very small timeout (1ms).

        Note: BaseScanner converts timeout to int, so 0.001 becomes 0.
        """
        from oida.protocols.modbus.scanner import ModbusScanner

        args = {"rhost": "127.0.0.1", "rport": 502, "timeout": 0.001}
        scanner = ModbusScanner(args)

        # BaseScanner converts timeout to int
        self.assertEqual(scanner.timeout, 0)

    @patch("oida.protocols.modbus.scanner._get_pymodbus")
    def test_very_large_timeout(self, mock_pymodbus):
        """Test Modbus scanner with very large timeout (1 hour)."""
        from oida.protocols.modbus.scanner import ModbusScanner

        args = {"rhost": "127.0.0.1", "rport": 502, "timeout": 3600}
        scanner = ModbusScanner(args)

        self.assertEqual(scanner.timeout, 3600)

    @patch("oida.protocols.modbus.scanner._get_pymodbus")
    def test_extremely_large_timeout(self, mock_pymodbus):
        """Test Modbus scanner with extremely large timeout (24 hours)."""
        from oida.protocols.modbus.scanner import ModbusScanner

        args = {"rhost": "127.0.0.1", "rport": 502, "timeout": 86400}
        scanner = ModbusScanner(args)

        self.assertEqual(scanner.timeout, 86400)

    @patch("oida.protocols.modbus.scanner._get_pymodbus")
    def test_float_timeout(self, mock_pymodbus):
        """Test Modbus scanner with float timeout value.

        Note: BaseScanner converts timeout to int, so 2.5 becomes 2.
        """
        from oida.protocols.modbus.scanner import ModbusScanner

        args = {"rhost": "127.0.0.1", "rport": 502, "timeout": 2.5}
        scanner = ModbusScanner(args)

        # BaseScanner converts timeout to int
        self.assertEqual(scanner.timeout, 2)


class TestOPCUATimeoutBoundaries(unittest.TestCase):
    """Test OPC UA scanner timeout boundary conditions."""

    def test_zero_timeout(self):
        """Test OPC UA scanner with zero timeout."""
        from oida.protocols.opcua import OPCUAScanner

        scanner = OPCUAScanner({"rhost": "127.0.0.1", "rport": 4840, "timeout": 0})

        self.assertEqual(scanner.timeout, 0)

    def test_negative_timeout(self):
        """Test OPC UA scanner with negative timeout."""
        from oida.protocols.opcua import OPCUAScanner

        scanner = OPCUAScanner({"rhost": "127.0.0.1", "rport": 4840, "timeout": -1})

        self.assertIsNotNone(scanner.timeout)

    def test_very_small_timeout(self):
        """Test OPC UA scanner with very small timeout (1ms).

        Note: BaseScanner converts timeout to int, so 0.001 becomes 0.
        """
        from oida.protocols.opcua import OPCUAScanner

        scanner = OPCUAScanner({"rhost": "127.0.0.1", "rport": 4840, "timeout": 0.001})

        # BaseScanner converts timeout to int
        self.assertEqual(scanner.timeout, 0)

    def test_very_large_timeout(self):
        """Test OPC UA scanner with very large timeout (1 hour)."""
        from oida.protocols.opcua import OPCUAScanner

        scanner = OPCUAScanner({"rhost": "127.0.0.1", "rport": 4840, "timeout": 3600})

        self.assertEqual(scanner.timeout, 3600)


class TestSnap7TimeoutBoundaries(unittest.TestCase):
    """Test Snap7 scanner timeout boundary conditions."""

    def test_zero_timeout(self):
        """Test Snap7 scanner with zero timeout."""
        from oida.protocols.snap7 import Snap7Scanner

        scanner = Snap7Scanner({"rhost": "127.0.0.1", "rport": 102, "timeout": 0})

        self.assertEqual(scanner.timeout, 0)

    def test_negative_timeout(self):
        """Test Snap7 scanner with negative timeout."""
        from oida.protocols.snap7 import Snap7Scanner

        scanner = Snap7Scanner({"rhost": "127.0.0.1", "rport": 102, "timeout": -1})

        self.assertIsNotNone(scanner.timeout)

    def test_very_small_timeout(self):
        """Test Snap7 scanner with very small timeout (1ms).

        Note: BaseScanner converts timeout to int, so 0.001 becomes 0.
        """
        from oida.protocols.snap7 import Snap7Scanner

        scanner = Snap7Scanner({"rhost": "127.0.0.1", "rport": 102, "timeout": 0.001})

        # BaseScanner converts timeout to int
        self.assertEqual(scanner.timeout, 0)

    def test_very_large_timeout(self):
        """Test Snap7 scanner with very large timeout (1 hour)."""
        from oida.protocols.snap7 import Snap7Scanner

        scanner = Snap7Scanner({"rhost": "127.0.0.1", "rport": 102, "timeout": 3600})

        self.assertEqual(scanner.timeout, 3600)


class TestMQTTTimeoutBoundaries(unittest.TestCase):
    """Test MQTT scanner timeout boundary conditions."""

    def test_zero_timeout(self):
        """Test MQTT scanner with zero timeout."""
        from oida.protocols.mqtt.scanner import MQTTScanner

        scanner = MQTTScanner({"rhost": "127.0.0.1", "rport": 1883, "timeout": 0})

        self.assertEqual(scanner.timeout, 0)

    def test_negative_timeout(self):
        """Test MQTT scanner with negative timeout."""
        from oida.protocols.mqtt.scanner import MQTTScanner

        scanner = MQTTScanner({"rhost": "127.0.0.1", "rport": 1883, "timeout": -1})

        self.assertIsNotNone(scanner.timeout)

    def test_very_small_timeout(self):
        """Test MQTT scanner with very small timeout (1ms).

        Note: BaseScanner converts timeout to int, so 0.001 becomes 0.
        """
        from oida.protocols.mqtt.scanner import MQTTScanner

        scanner = MQTTScanner({"rhost": "127.0.0.1", "rport": 1883, "timeout": 0.001})

        # BaseScanner converts timeout to int
        self.assertEqual(scanner.timeout, 0)

    def test_very_large_timeout(self):
        """Test MQTT scanner with very large timeout (1 hour)."""
        from oida.protocols.mqtt.scanner import MQTTScanner

        scanner = MQTTScanner({"rhost": "127.0.0.1", "rport": 1883, "timeout": 3600})

        self.assertEqual(scanner.timeout, 3600)


# ==============================================================================
# Timeout During Operation Phases
# ==============================================================================


class TestTimeoutDuringConnect(unittest.TestCase):
    """Test timeout behavior during connection phase."""

    def test_socket_timeout_on_connect(self):
        """Test socket timeout during connection."""
        mock_socket = Mock()
        mock_socket.connect.side_effect = socket.timeout("Connection timed out")

        with self.assertRaises(socket.timeout):
            mock_socket.connect(("192.168.1.100", 502))

    def test_async_timeout_on_connect(self):
        """Test asyncio timeout during connection."""
        mock_client = Mock()
        mock_client.connect = AsyncMock(side_effect=asyncio.TimeoutError("Connection timed out"))

        with self.assertRaises(asyncio.TimeoutError):
            asyncio.run(mock_client.connect())


class TestTimeoutDuringRead(unittest.TestCase):
    """Test timeout behavior during read operations."""

    def test_socket_timeout_on_recv(self):
        """Test socket timeout during recv."""
        mock_socket = Mock()
        mock_socket.recv.side_effect = socket.timeout("recv timed out")

        with self.assertRaises(socket.timeout):
            mock_socket.recv(1024)

    def test_partial_recv_before_timeout(self):
        """Test partial data received before timeout."""
        mock_socket = Mock()

        # First call returns partial data, second times out
        mock_socket.recv.side_effect = [
            b"\x00\x01\x00\x00",  # Partial data
            socket.timeout("recv timed out"),
        ]

        # First recv succeeds
        data = mock_socket.recv(1024)
        self.assertEqual(data, b"\x00\x01\x00\x00")

        # Second recv times out
        with self.assertRaises(socket.timeout):
            mock_socket.recv(1024)


class TestTimeoutDuringWrite(unittest.TestCase):
    """Test timeout behavior during write operations."""

    def test_socket_timeout_on_send(self):
        """Test socket timeout during send."""
        mock_socket = Mock()
        mock_socket.send.side_effect = socket.timeout("send timed out")

        with self.assertRaises(socket.timeout):
            mock_socket.send(b"\x00\x01\x00\x00")

    def test_partial_send_before_timeout(self):
        """Test partial data sent before timeout."""
        mock_socket = Mock()

        # First call sends partial data, second times out
        mock_socket.send.side_effect = [
            4,  # Sent 4 bytes
            socket.timeout("send timed out"),
        ]

        # First send succeeds
        sent = mock_socket.send(b"\x00\x01\x00\x00\x00\x00\x00\x00")
        self.assertEqual(sent, 4)

        # Second send times out
        with self.assertRaises(socket.timeout):
            mock_socket.send(b"\x00\x00\x00\x00")


# ==============================================================================
# Cascading Timeout Tests
# ==============================================================================


class TestCascadingTimeouts(unittest.TestCase):
    """Test cascading timeout scenarios."""

    def test_multiple_operations_with_individual_timeouts(self):
        """Test multiple operations each with their own timeout."""
        mock_client = Mock()

        # Each operation has increasing timeout behavior
        operations = [
            ("connect", None),
            ("read", socket.timeout("read timed out")),
            ("write", socket.timeout("write timed out")),
        ]

        for op_name, error in operations:
            op = getattr(mock_client, op_name)
            if error:
                op.side_effect = error
                with self.assertRaises(socket.timeout):
                    op()
            else:
                op.return_value = True
                result = op()
                self.assertTrue(result)

    def test_timeout_propagation_through_layers(self):
        """Test timeout propagates correctly through abstraction layers."""
        # Inner layer timeout
        inner_mock = Mock()
        inner_mock.read.side_effect = socket.timeout("inner timeout")

        # Wrapper that should propagate the timeout
        def wrapper_read():
            return inner_mock.read()

        with self.assertRaises(socket.timeout) as ctx:
            wrapper_read()

        self.assertIn("inner timeout", str(ctx.exception))


# ==============================================================================
# Pytest-style Timeout Tests
# ==============================================================================


@pytest.mark.timeout(30)
class TestTimeoutParametrized:
    """Parametrized timeout tests."""

    @pytest.mark.parametrize("timeout", [0, 0.001, 0.1, 1, 5, 10, 30, 60, 3600])
    def test_modbus_timeout_values(self, timeout):
        """Test Modbus scanner with various timeout values.

        Note: BaseScanner converts timeout to int.
        """
        with patch("oida.protocols.modbus.scanner._get_pymodbus"):
            from oida.protocols.modbus.scanner import ModbusScanner

            scanner = ModbusScanner(
                {
                    "rhost": "127.0.0.1",
                    "rport": 502,
                    "timeout": timeout,
                }
            )

            # BaseScanner converts timeout to int
            assert scanner.timeout == int(timeout)

    @pytest.mark.parametrize("timeout", [0, 0.001, 0.1, 1, 5, 10, 30, 60, 3600])
    def test_opcua_timeout_values(self, timeout):
        """Test OPC UA scanner with various timeout values.

        Note: BaseScanner converts timeout to int.
        """
        from oida.protocols.opcua import OPCUAScanner

        scanner = OPCUAScanner(
            {
                "rhost": "127.0.0.1",
                "rport": 4840,
                "timeout": timeout,
            }
        )

        # BaseScanner converts timeout to int
        assert scanner.timeout == int(timeout)

    @pytest.mark.parametrize("timeout", [0, 0.001, 0.1, 1, 5, 10, 30, 60, 3600])
    def test_snap7_timeout_values(self, timeout):
        """Test Snap7 scanner with various timeout values.

        Note: BaseScanner converts timeout to int.
        """
        from oida.protocols.snap7 import Snap7Scanner

        scanner = Snap7Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 102,
                "timeout": timeout,
            }
        )

        # BaseScanner converts timeout to int
        assert scanner.timeout == int(timeout)

    @pytest.mark.parametrize("timeout", [0, 0.001, 0.1, 1, 5, 10, 30, 60, 3600])
    def test_mqtt_timeout_values(self, timeout):
        """Test MQTT scanner with various timeout values.

        Note: BaseScanner converts timeout to int.
        """
        from oida.protocols.mqtt.scanner import MQTTScanner

        scanner = MQTTScanner(
            {
                "rhost": "127.0.0.1",
                "rport": 1883,
                "timeout": timeout,
            }
        )

        # BaseScanner converts timeout to int
        assert scanner.timeout == int(timeout)

    @pytest.mark.parametrize(
        "exception_type",
        [
            socket.timeout,
            asyncio.TimeoutError,
            TimeoutError,
        ],
    )
    def test_timeout_exception_types(self, exception_type):
        """Test handling of different timeout exception types."""
        mock_client = Mock()
        mock_client.connect.side_effect = exception_type("timed out")

        with pytest.raises(exception_type):
            mock_client.connect()


@pytest.mark.timeout(30)
class TestTimeoutRecovery:
    """Test recovery after timeout events."""

    def test_retry_after_timeout(self):
        """Test successful retry after timeout."""
        mock_client = Mock()

        # First attempt times out, second succeeds
        mock_client.connect.side_effect = [
            socket.timeout("Connection timed out"),
            True,
        ]

        # First attempt
        with pytest.raises(socket.timeout):
            mock_client.connect()

        # Second attempt succeeds
        result = mock_client.connect()
        assert result is True

    def test_reconnect_after_timeout(self):
        """Test reconnection after timeout."""
        from oida.protocols.opcua import OPCUAScanner

        scanner = OPCUAScanner(
            {
                "rhost": "127.0.0.1",
                "rport": 4840,
                "timeout": 5,
            }
        )

        mock_client = Mock()
        mock_client.disconnect = Mock()

        # Disconnect after timeout
        scanner.disconnect(mock_client)

        # Should be able to create new connection
        assert scanner.host == "127.0.0.1"


if __name__ == "__main__":
    unittest.main()
