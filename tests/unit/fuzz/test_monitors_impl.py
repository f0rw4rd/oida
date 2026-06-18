"""
Tests for monitor implementations.

Tests cover:
- PingMonitor: ICMP reachability checks
- SocketHealthMonitor: TCP port checks
- ModbusMonitor: Modbus protocol health checks
- IEC104Monitor: IEC 60870-5-104 TESTFR checks
- MMSMonitor: MMS Identify request checks
"""

import pytest
import socket
from unittest.mock import Mock, MagicMock, patch


# =============================================================================
# Test PingMonitor
# =============================================================================


class TestPingMonitorCreation:
    """Tests for PingMonitor instantiation."""

    def test_basic_creation(self):
        """PingMonitor can be created."""
        from src.oida.fuzz.monitors.network import PingMonitor

        monitor = PingMonitor("192.168.1.1")
        assert monitor.host == "192.168.1.1"

    def test_creation_with_options(self):
        """PingMonitor accepts optional parameters."""
        from src.oida.fuzz.monitors.network import PingMonitor

        monitor = PingMonitor("10.0.0.1", retry_count=5, ping_count=3, failure_threshold=3)
        assert monitor.retry_count == 5
        assert monitor.ping_count == "3"
        assert monitor.failure_threshold == 3

    def test_initial_failure_count_zero(self):
        """Initial consecutive failures is zero."""
        from src.oida.fuzz.monitors.network import PingMonitor

        monitor = PingMonitor("192.168.1.1")
        assert monitor.consecutive_failures == 0


class TestPingMonitorCheckAlive:
    """Tests for PingMonitor health check logic."""

    def test_check_alive_success_resets_failures(self):
        """Successful ping resets failure counter."""
        from src.oida.fuzz.monitors.network import PingMonitor

        mock_runner = Mock()
        mock_runner.run.return_value = Mock(returncode=0)

        monitor = PingMonitor("192.168.1.1", command_runner=mock_runner)
        monitor.consecutive_failures = 2

        result = monitor._check_alive(None)

        assert result is True
        assert monitor.consecutive_failures == 0

    def test_check_alive_failure_increments_counter(self):
        """Failed ping increments failure counter."""
        from src.oida.fuzz.monitors.network import PingMonitor

        mock_runner = Mock()
        mock_runner.run.return_value = Mock(returncode=1)

        monitor = PingMonitor(
            "192.168.1.1", command_runner=mock_runner, retry_count=1, failure_threshold=3
        )

        result = monitor._check_alive(Mock())

        assert result is True  # Below threshold
        assert monitor.consecutive_failures == 1

    def test_check_alive_exceeds_threshold(self):
        """Raises BoofuzzFailure when threshold exceeded and recovery fails."""
        from src.oida.fuzz.monitors.network import PingMonitor
        from boofuzz.exception import BoofuzzFailure

        mock_runner = Mock()
        mock_runner.run.return_value = Mock(returncode=1)

        monitor = PingMonitor(
            "192.168.1.1", command_runner=mock_runner, retry_count=1, failure_threshold=2
        )
        monitor.consecutive_failures = 1  # Already had one failure

        with pytest.raises(BoofuzzFailure):
            monitor._check_alive(Mock())

        assert monitor.consecutive_failures >= 2

    def test_check_alive_retries_on_failure(self):
        """Ping is retried on failure."""
        from src.oida.fuzz.monitors.network import PingMonitor

        mock_runner = Mock()
        # First fails, second succeeds
        mock_runner.run.side_effect = [Mock(returncode=1), Mock(returncode=0)]

        monitor = PingMonitor(
            "192.168.1.1", command_runner=mock_runner, retry_count=2, retry_delay=0.001
        )

        result = monitor._check_alive(Mock())

        assert result is True
        assert mock_runner.run.call_count == 2


class TestPingMonitorPrePostSend:
    """Tests for PingMonitor pre_send and post_send."""

    def test_pre_send_calls_check_alive(self):
        """pre_send triggers health check."""
        from src.oida.fuzz.monitors.network import PingMonitor

        mock_runner = Mock()
        mock_runner.run.return_value = Mock(returncode=0)

        monitor = PingMonitor("192.168.1.1", command_runner=mock_runner)
        result = monitor.pre_send(fuzz_data_logger=Mock())

        assert result is True
        mock_runner.run.assert_called()

    def test_post_send_calls_check_alive(self):
        """post_send triggers health check."""
        from src.oida.fuzz.monitors.network import PingMonitor

        mock_runner = Mock()
        mock_runner.run.return_value = Mock(returncode=0)

        monitor = PingMonitor("192.168.1.1", command_runner=mock_runner)
        result = monitor.post_send(fuzz_data_logger=Mock())

        assert result is True


class TestPingMonitorRepr:
    """Tests for PingMonitor string representations."""

    def test_repr(self):
        """repr shows monitor state."""
        from src.oida.fuzz.monitors.network import PingMonitor

        monitor = PingMonitor("192.168.1.1")
        assert "192.168.1.1" in repr(monitor)

    def test_str(self):
        """str shows friendly description."""
        from src.oida.fuzz.monitors.network import PingMonitor

        monitor = PingMonitor("192.168.1.1")
        assert "192.168.1.1" in str(monitor)


# =============================================================================
# Test SocketHealthMonitor
# =============================================================================


class TestSocketHealthMonitorCreation:
    """Tests for SocketHealthMonitor instantiation."""

    def test_basic_creation(self):
        """SocketHealthMonitor can be created."""
        from src.oida.fuzz.monitors.network import SocketHealthMonitor

        monitor = SocketHealthMonitor("192.168.1.1", 80)
        assert monitor.host == "192.168.1.1"
        assert monitor.port == 80

    def test_creation_with_options(self):
        """SocketHealthMonitor accepts optional parameters."""
        from src.oida.fuzz.monitors.network import SocketHealthMonitor

        monitor = SocketHealthMonitor(
            "10.0.0.1", 8080, retry_count=5, timeout=5, failure_threshold=3
        )
        assert monitor.retry_count == 5
        assert monitor.timeout == 5
        assert monitor.failure_threshold == 3


class TestSocketHealthMonitorCheckAlive:
    """Tests for SocketHealthMonitor health check logic."""

    def test_check_alive_success(self):
        """Successful socket connection returns True."""
        from src.oida.fuzz.monitors.network import SocketHealthMonitor

        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket

            monitor = SocketHealthMonitor("192.168.1.1", 80)
            result = monitor._check_alive(Mock())

            assert result is True
            mock_socket.connect.assert_called_with(("192.168.1.1", 80))
            mock_socket.close.assert_called()

    def test_check_alive_failure(self):
        """Failed socket connection increments failures."""
        from src.oida.fuzz.monitors.network import SocketHealthMonitor

        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket.connect.side_effect = socket.error("Connection refused")
            mock_socket_class.return_value = mock_socket

            monitor = SocketHealthMonitor(
                "192.168.1.1", 80, retry_count=1, failure_threshold=3, retry_delay=0.001
            )

            result = monitor._check_alive(Mock())

            assert result is True  # Below threshold
            assert monitor.consecutive_failures == 1


# =============================================================================
# Test ModbusMonitor
# =============================================================================


class TestModbusMonitorCreation:
    """Tests for ModbusMonitor instantiation."""

    def test_basic_creation(self):
        """ModbusMonitor can be created."""
        from src.oida.fuzz.monitors.industrial import ModbusMonitor

        monitor = ModbusMonitor("192.168.1.1")
        assert monitor.host == "192.168.1.1"
        assert monitor.port == 502  # Default Modbus port

    def test_creation_with_options(self):
        """ModbusMonitor accepts optional parameters."""
        from src.oida.fuzz.monitors.industrial import ModbusMonitor

        monitor = ModbusMonitor(
            "10.0.0.1",
            port=10502,
            timeout=5.0,
            check_interval=10,
            retry_count=3,
            failure_threshold=5,
        )
        assert monitor.port == 10502
        assert monitor.timeout == 5.0
        assert monitor.check_interval == 10


class TestModbusMonitorCreateRequest:
    """Tests for ModbusMonitor request creation."""

    def test_create_read_request_format(self):
        """Read request has correct Modbus TCP format."""
        from src.oida.fuzz.monitors.industrial import ModbusMonitor

        monitor = ModbusMonitor("192.168.1.1")
        request = monitor._create_read_request()

        # Check minimum length (12 bytes for Modbus TCP)
        assert len(request) == 12

        # Check Transaction ID
        assert request[0:2] == b"\x00\x01"

        # Check Protocol ID (Modbus = 0)
        assert request[2:4] == b"\x00\x00"

        # Check Function Code (3 = Read Holding Registers)
        assert request[7] == 0x03


class TestModbusMonitorBaseline:
    """Tests for ModbusMonitor baseline tracking."""

    def test_store_baseline(self):
        """Baseline is stored on first success."""
        from src.oida.fuzz.monitors.industrial import ModbusMonitor

        monitor = ModbusMonitor("192.168.1.1")

        # Simulate a valid Modbus response
        response = b"\x00\x01\x00\x00\x00\x05\x01\x03\x02\x00\x00"
        logger = Mock()

        monitor._store_baseline(response, logger)

        assert monitor.baseline_established is True
        assert monitor.baseline_response == response
        assert monitor.baseline_function_code == 0x03

    def test_compare_responses_same(self):
        """Same function code passes comparison."""
        from src.oida.fuzz.monitors.industrial import ModbusMonitor

        monitor = ModbusMonitor("192.168.1.1")
        monitor.baseline_function_code = 0x03

        # Response with same function code
        response = b"\x00\x01\x00\x00\x00\x05\x01\x03\x02\x00\x00"
        result = monitor._compare_responses(response, Mock())

        assert result is True

    def test_compare_responses_error_code(self):
        """Error function code fails comparison."""
        from src.oida.fuzz.monitors.industrial import ModbusMonitor

        monitor = ModbusMonitor("192.168.1.1")
        monitor.baseline_function_code = 0x03

        # Response with error code (0x03 + 0x80 = 0x83)
        response = b"\x00\x01\x00\x00\x00\x03\x01\x83\x02"
        logger = Mock()
        result = monitor._compare_responses(response, logger)

        assert result is False
        logger.log_fail.assert_called()


class TestModbusMonitorCheckAlive:
    """Tests for ModbusMonitor health check logic."""

    def test_check_alive_success(self):
        """Successful Modbus read returns True."""
        from src.oida.fuzz.monitors.industrial import ModbusMonitor

        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket.recv.return_value = b"\x00\x01\x00\x00\x00\x05\x01\x03\x02\x00\x00"
            mock_socket_class.return_value = mock_socket

            monitor = ModbusMonitor("192.168.1.1")
            monitor.last_check_time = None

            result = monitor._check_alive(Mock())

            assert result is True
            assert monitor.consecutive_failures == 0

    def test_check_alive_timeout(self):
        """Socket timeout increments failures."""
        from src.oida.fuzz.monitors.industrial import ModbusMonitor

        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket.connect.side_effect = socket.timeout()
            mock_socket_class.return_value = mock_socket

            monitor = ModbusMonitor("192.168.1.1", retry_count=1, failure_threshold=3)
            monitor.last_check_time = None

            result = monitor._check_alive(Mock())

            assert result is True  # Below threshold
            assert monitor.consecutive_failures == 1


class TestModbusMonitorPrePostSend:
    """Tests for ModbusMonitor pre_send and post_send."""

    def test_pre_send_rate_limiting(self):
        """pre_send respects check_interval."""
        from src.oida.fuzz.monitors.industrial import ModbusMonitor

        monitor = ModbusMonitor("192.168.1.1", check_interval=10)

        # pre_send increments test_case_count on each call
        # So after 9 calls, count will be 9 (started at 0)
        for i in range(9):
            result = monitor.pre_send()
            assert result is True

        # After 9 calls to pre_send, test_case_count should be 9
        assert monitor.test_case_count == 9


# =============================================================================
# Test IEC104Monitor
# =============================================================================


class TestIEC104MonitorCreation:
    """Tests for IEC104Monitor instantiation."""

    def test_basic_creation(self):
        """IEC104Monitor can be created."""
        from src.oida.fuzz.monitors.industrial import IEC104Monitor

        monitor = IEC104Monitor("192.168.1.1")
        assert monitor.host == "192.168.1.1"
        assert monitor.port == 2404  # Default IEC 104 port

    def test_initial_state_disconnected(self):
        """Initial state is DISCONNECTED."""
        from src.oida.fuzz.monitors.industrial import IEC104Monitor, IEC104States

        monitor = IEC104Monitor("192.168.1.1")
        assert monitor.state == IEC104States.DISCONNECTED


class TestIEC104MonitorTESTFR:
    """Tests for IEC104Monitor TESTFR frames."""

    def test_create_testfr_format(self):
        """TESTFR request has correct format."""
        from src.oida.fuzz.monitors.industrial import IEC104Monitor

        monitor = IEC104Monitor("192.168.1.1")
        testfr = monitor._create_testfr()

        assert len(testfr) == 6
        assert testfr[0] == 0x68  # Start byte
        assert testfr[1] == 0x04  # APDU length
        assert testfr[2] == 0x43  # TESTFR act


class TestIEC104MonitorCheckAlive:
    """Tests for IEC104Monitor health check logic."""

    def test_check_alive_success(self):
        """Successful TESTFR ACK returns True."""
        from src.oida.fuzz.monitors.industrial import IEC104Monitor

        mock_socket = MagicMock()
        # TESTFR ACK response
        mock_socket.recv.return_value = bytes([0x68, 0x04, 0x83, 0x00, 0x00, 0x00])

        monitor = IEC104Monitor("192.168.1.1")
        monitor.socket = mock_socket

        result = monitor._check_alive_once(Mock())

        assert result is True
        assert monitor.baseline_established is True

    def test_check_alive_invalid_response(self):
        """Invalid TESTFR response returns False."""
        from src.oida.fuzz.monitors.industrial import IEC104Monitor

        mock_socket = MagicMock()
        # Invalid response (wrong byte 2)
        mock_socket.recv.return_value = bytes([0x68, 0x04, 0x00, 0x00, 0x00, 0x00])

        monitor = IEC104Monitor("192.168.1.1")
        monitor.socket = mock_socket

        result = monitor._check_alive_once(Mock())

        assert result is False

    def test_check_alive_no_socket(self):
        """Returns False when no socket and reconnect fails."""
        from src.oida.fuzz.monitors.industrial import IEC104Monitor

        monitor = IEC104Monitor("192.168.1.1")
        monitor.socket = None
        monitor._connect = Mock(return_value=False)

        result = monitor._check_alive_once(Mock())

        assert result is False


# =============================================================================
# Test MMSMonitor
# =============================================================================


class TestMMSMonitorCreation:
    """Tests for MMSMonitor instantiation."""

    def test_basic_creation(self):
        """MMSMonitor can be created."""
        from src.oida.fuzz.monitors.industrial import MMSMonitor

        monitor = MMSMonitor("192.168.1.1")
        assert monitor.host == "192.168.1.1"
        assert monitor.port == 102  # Default MMS/ISO-on-TCP port

    def test_initial_state(self):
        """Initial state is not connected."""
        from src.oida.fuzz.monitors.industrial import MMSMonitor

        monitor = MMSMonitor("192.168.1.1")
        assert monitor.connected is False


class TestMMSMonitorTPKT:
    """Tests for MMSMonitor TPKT building."""

    def test_build_tpkt_header(self):
        """TPKT header is correct."""
        from src.oida.fuzz.monitors.industrial import MMSMonitor

        monitor = MMSMonitor("192.168.1.1")

        data = b"\x01\x02\x03"
        tpkt = monitor._build_tpkt(data)

        assert tpkt[0] == 0x03  # Version
        assert tpkt[1] == 0x00  # Reserved
        # Length = 4 (header) + 3 (data) = 7
        assert tpkt[2:4] == b"\x00\x07"
        assert tpkt[4:] == data


class TestMMSMonitorConnect:
    """Tests for MMSMonitor connection logic."""

    def test_connect_success(self):
        """Successful connection returns True."""
        from src.oida.fuzz.monitors.industrial import MMSMonitor

        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            # COTP CC response
            mock_socket.recv.side_effect = [
                bytes([0x03, 0x00, 0x00, 0x0B, 0x02, 0xD0, 0x00, 0x00, 0x00, 0x00, 0x00]),
                bytes([0x03, 0x00] + [0x00] * 20),  # MMS Initiate response
            ]
            mock_socket_class.return_value = mock_socket

            monitor = MMSMonitor("192.168.1.1")
            result = monitor._connect()

            assert result is True
            assert monitor.connected is True

    def test_connect_cotp_failure(self):
        """Connection fails on COTP rejection."""
        from src.oida.fuzz.monitors.industrial import MMSMonitor

        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            # Not a CC response (0xd0)
            mock_socket.recv.return_value = bytes([0x03, 0x00, 0x00, 0x07, 0x02, 0x00, 0x00])
            mock_socket_class.return_value = mock_socket

            monitor = MMSMonitor("192.168.1.1")
            result = monitor._connect()

            assert result is False


class TestMMSMonitorCheckAlive:
    """Tests for MMSMonitor health check logic."""

    def test_check_alive_success(self):
        """Successful Identify returns True."""
        from src.oida.fuzz.monitors.industrial import MMSMonitor

        with patch.object(MMSMonitor, "_connect", return_value=True):
            with patch.object(MMSMonitor, "_build_mms_identify", return_value=b"\xa0\x00"):
                mock_socket = MagicMock()
                mock_socket.recv.return_value = bytes([0x03, 0x00] + [0x00] * 20)

                monitor = MMSMonitor("192.168.1.1")
                monitor.socket = mock_socket
                monitor.connected = True

                result = monitor._check_alive_once(Mock())

                assert result is True
                assert monitor.baseline_established is True


class TestMMSMonitorClose:
    """Tests for MMSMonitor close method."""

    def test_close_socket(self):
        """close() closes socket and resets state."""
        from src.oida.fuzz.monitors.industrial import MMSMonitor

        mock_socket = MagicMock()
        monitor = MMSMonitor("192.168.1.1")
        monitor.socket = mock_socket
        monitor.connected = True

        monitor.close()

        mock_socket.close.assert_called_once()
        assert monitor.socket is None
        assert monitor.connected is False


# =============================================================================
# Test Failure Threshold Behavior
# =============================================================================


class TestFailureThresholdBehavior:
    """Tests for failure threshold behavior across monitors."""

    def test_ping_monitor_threshold(self):
        """PingMonitor respects failure threshold."""
        from src.oida.fuzz.monitors.network import PingMonitor

        mock_runner = Mock()
        mock_runner.run.return_value = Mock(returncode=1)

        monitor = PingMonitor(
            "192.168.1.1", command_runner=mock_runner, retry_count=1, failure_threshold=3
        )

        logger = Mock()

        # First two failures should be tolerated
        for _ in range(2):
            monitor.last_check_time = None  # Reset rate limiter
            result = monitor._check_alive(logger)
            assert result is True

        # Third failure should raise BoofuzzFailure (threshold exceeded, recovery fails)
        from boofuzz.exception import BoofuzzFailure

        monitor.last_check_time = None  # Reset rate limiter
        with pytest.raises(BoofuzzFailure):
            monitor._check_alive(logger)

    def test_modbus_monitor_threshold(self):
        """ModbusMonitor respects failure threshold."""
        from src.oida.fuzz.monitors.industrial import ModbusMonitor
        from boofuzz.exception import BoofuzzFailure

        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket.connect.side_effect = socket.timeout()
            mock_socket_class.return_value = mock_socket

            monitor = ModbusMonitor("192.168.1.1", retry_count=1, failure_threshold=2)
            monitor.last_check_time = None

            logger = Mock()

            # First failure tolerated
            result = monitor._check_alive(logger)
            assert result is True
            assert monitor.consecutive_failures == 1

            # Reset time to allow check
            monitor.last_check_time = None

            # Second failure should raise BoofuzzFailure (threshold exceeded, recovery fails)
            with pytest.raises(BoofuzzFailure):
                monitor._check_alive(logger)


# =============================================================================
# Test BaseMonitor Interface
# =============================================================================


class TestBaseMonitorInterface:
    """Tests for BaseMonitor interface compliance."""

    def test_ping_monitor_is_base_monitor(self):
        """PingMonitor inherits from BaseMonitor."""
        from src.oida.fuzz.monitors.network import PingMonitor
        from boofuzz.monitors import BaseMonitor

        monitor = PingMonitor("192.168.1.1")
        assert isinstance(monitor, BaseMonitor)

    def test_socket_health_monitor_is_base_monitor(self):
        """SocketHealthMonitor inherits from BaseMonitor."""
        from src.oida.fuzz.monitors.network import SocketHealthMonitor
        from boofuzz.monitors import BaseMonitor

        monitor = SocketHealthMonitor("192.168.1.1", 80)
        assert isinstance(monitor, BaseMonitor)

    def test_modbus_monitor_is_base_monitor(self):
        """ModbusMonitor inherits from BaseMonitor."""
        from src.oida.fuzz.monitors.industrial import ModbusMonitor
        from boofuzz.monitors import BaseMonitor

        monitor = ModbusMonitor("192.168.1.1")
        assert isinstance(monitor, BaseMonitor)

    def test_iec104_monitor_is_base_monitor(self):
        """IEC104Monitor inherits from BaseMonitor."""
        from src.oida.fuzz.monitors.industrial import IEC104Monitor
        from boofuzz.monitors import BaseMonitor

        monitor = IEC104Monitor("192.168.1.1")
        assert isinstance(monitor, BaseMonitor)

    def test_mms_monitor_is_base_monitor(self):
        """MMSMonitor inherits from BaseMonitor."""
        from src.oida.fuzz.monitors.industrial import MMSMonitor
        from boofuzz.monitors import BaseMonitor

        monitor = MMSMonitor("192.168.1.1")
        assert isinstance(monitor, BaseMonitor)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
