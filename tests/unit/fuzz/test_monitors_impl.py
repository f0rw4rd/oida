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

    def test_check_alive_success_clears_failures_after_streak(self):
        """A clean-check STREAK clears failures; a single success does not.

        New semantics (Bug 4 fix): a lone success no longer wipes accumulated
        failure history -- otherwise a half-crashed target that answers only
        intermittently would never trip the crash threshold. failure_threshold
        consecutive successful checks are required to reset the counter.
        """
        from src.oida.fuzz.monitors.network import PingMonitor

        mock_runner = Mock()
        mock_runner.run.return_value = Mock(returncode=0)

        monitor = PingMonitor("192.168.1.1", command_runner=mock_runner)
        monitor.consecutive_failures = 2

        # One good check is NOT enough to clear the failure history.
        monitor.last_check_time = None
        assert monitor._check_alive(None) is True
        assert monitor.consecutive_failures == 2

        # A full streak of failure_threshold clean checks clears it.
        for _ in range(monitor.failure_threshold):
            monitor.last_check_time = None
            assert monitor._check_alive(None) is True
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

        # Bug 4 fix: a fully-failed round is NOT healthy even below threshold.
        assert result is False
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

        monitor = PingMonitor("192.168.1.1", command_runner=mock_runner, retry_count=2)

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

            monitor = SocketHealthMonitor("192.168.1.1", 80, retry_count=1, failure_threshold=3)

            result = monitor._check_alive(Mock())

            # Bug 4 fix: a fully-failed round is NOT healthy even below threshold.
            assert result is False
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

            # Bug 4 fix: a fully-failed round is NOT healthy even below threshold.
            assert result is False
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


class TestIEC104MonitorCrashDetection:
    """Regression tests: IEC104 health checks must route through _check_alive().

    Previously IEC104Monitor overrode pre_send and, when DISCONNECTED/ERROR,
    called _connect() directly instead of _check_alive(). After the first failed
    check flipped state to ERROR, every later probe took the _connect()-only
    branch, so a genuinely down target was reported "not alive" but never counted
    toward failure_threshold, never recorded to the CrashTracker, and never
    triggered recovery/restart. These tests pin the corrected behavior.
    """

    def _make_down_monitor(self):
        """IEC104Monitor whose connect always fails (target is down)."""
        from src.oida.fuzz.monitors.industrial import IEC104Monitor
        from src.oida.fuzz.monitors.base import CrashTracker

        tracker = CrashTracker(target="192.168.1.1:2404")
        monitor = IEC104Monitor(
            "192.168.1.1",
            check_interval=1,
            retry_count=1,
            failure_threshold=2,
        )
        # No recovery possible -> _check_alive raises BoofuzzFailure on crash.
        monitor.max_recovery_attempts = 0
        monitor.crash_tracker = tracker
        # Simulate a target that is down: every connect attempt fails.
        monitor._connect = Mock(return_value=False)
        # Avoid sleeping in the retry/recovery loops.
        monitor.last_check_time = None
        return monitor, tracker

    def test_pre_send_records_crash_when_target_down(self):
        """A persistently-down target must be recorded as a crash via _check_alive."""
        from boofuzz.exception import BoofuzzFailure

        monitor, tracker = self._make_down_monitor()

        # First probe: 1 failure (below threshold=2). Bug 4 fix: a fully-failed
        # round is reported as False (not healthy), but does not yet crash.
        assert monitor.pre_send(fuzz_data_logger=Mock()) is False
        assert monitor.consecutive_failures == 1
        assert tracker.crash_count == 0

        # Second probe: hits threshold -> crash detected. With
        # max_recovery_attempts=0, recovery is impossible so BoofuzzFailure raises.
        # Clear the rate-limit window so the check actually runs again.
        monitor.last_check_time = None
        with pytest.raises(BoofuzzFailure):
            monitor.pre_send(fuzz_data_logger=Mock())

        # The bug: crash was never recorded. Fix: crash IS recorded.
        assert monitor.crashed is True
        assert tracker.crash_count == 1

    def test_post_send_records_crash_when_target_down(self):
        """post_send must also drive crash accounting through _check_alive."""
        from boofuzz.exception import BoofuzzFailure

        monitor, tracker = self._make_down_monitor()

        # test_case_count must be a multiple of check_interval for the check to run.
        monitor.test_case_count = 1
        # Bug 4 fix: a fully-failed round reports False (not healthy) below threshold.
        assert monitor.post_send(fuzz_data_logger=Mock()) is False
        assert monitor.consecutive_failures == 1

        monitor.last_check_time = None
        with pytest.raises(BoofuzzFailure):
            monitor.post_send(fuzz_data_logger=Mock())

        assert tracker.crash_count == 1

    def test_no_bespoke_pre_send_override(self):
        """IEC104Monitor must inherit pre_send/post_send from ProtocolMonitor."""
        from src.oida.fuzz.monitors.industrial import IEC104Monitor
        from src.oida.fuzz.monitors.base import ProtocolMonitor

        assert IEC104Monitor.pre_send is ProtocolMonitor.pre_send
        assert IEC104Monitor.post_send is ProtocolMonitor.post_send


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

        # First two failures are below threshold: tolerated (no crash/raise), but
        # a fully-failed round now reports False (Bug 4 fix), not healthy.
        for _ in range(2):
            monitor.last_check_time = None  # Reset rate limiter
            result = monitor._check_alive(logger)
            assert result is False

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

            # First failure below threshold: tolerated (no raise) but reports
            # False (Bug 4 fix), not healthy.
            result = monitor._check_alive(logger)
            assert result is False
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


# =============================================================================
# Test CustomSSLSocketMonitor
# =============================================================================


def _make_ssl_monitor(target_ip="192.168.1.1", target_port=8443, **overrides):
    """Build a CustomSSLSocketMonitor from a minimal FuzzerConfig.

    retry_count / failure_threshold are monitor (not config) attributes, so they
    are applied to the instance after construction.
    """
    from src.oida.fuzz.monitors.network import CustomSSLSocketMonitor
    from src.oida.fuzz.core.config import FuzzerConfig

    config = FuzzerConfig(target_ip=target_ip, target_port=target_port)
    monitor = CustomSSLSocketMonitor(config)
    for attr, value in overrides.items():
        setattr(monitor, attr, value)
    return monitor


class TestCustomSSLSocketMonitorCreation:
    """Tests for CustomSSLSocketMonitor instantiation."""

    def test_basic_creation(self):
        """CustomSSLSocketMonitor takes host/port from the FuzzerConfig."""
        monitor = _make_ssl_monitor("10.0.0.5", 8281)
        assert monitor.host == "10.0.0.5"
        assert monitor.port == 8281
        assert monitor.check_interval == 1

    def test_is_protocol_monitor(self):
        """Migrated to ProtocolMonitor so it inherits shared crash detection."""
        from src.oida.fuzz.monitors.base import ProtocolMonitor

        monitor = _make_ssl_monitor()
        assert isinstance(monitor, ProtocolMonitor)
        assert hasattr(monitor, "_check_alive_once")


class TestCustomSSLSocketMonitorCheckAlive:
    """Tests for CustomSSLSocketMonitor health-check logic."""

    def test_check_alive_success(self):
        """Successful TLS handshake returns True and resets failures."""
        with patch("socket.socket"), patch("ssl.create_default_context") as mock_ctx:
            secure_sock = MagicMock()
            mock_ctx.return_value.wrap_socket.return_value = secure_sock

            monitor = _make_ssl_monitor("192.168.1.1", 8443)
            result = monitor._check_alive(Mock())

            assert result is True
            secure_sock.connect.assert_called_with(("192.168.1.1", 8443))
            assert monitor.consecutive_failures == 0

    def test_first_failure_does_not_raise(self):
        """A single connect failure below threshold must NOT raise (retry/threshold).

        Regression: the old BaseMonitor implementation raised BoofuzzFailure on the
        very first connect blip, turning a transient hiccup into a false crash.
        """
        with patch("socket.socket"), patch("ssl.create_default_context") as mock_ctx:
            secure_sock = MagicMock()
            secure_sock.connect.side_effect = OSError("Connection refused")
            mock_ctx.return_value.wrap_socket.return_value = secure_sock

            monitor = _make_ssl_monitor(retry_count=1, failure_threshold=3)
            result = monitor._check_alive(Mock())

            # The point of this test is that a single blip does NOT raise. It is
            # still reported as False (Bug 4 fix), not healthy, but fuzzing
            # continues (only crossing failure_threshold raises BoofuzzFailure).
            assert result is False  # below threshold -> keep fuzzing, but not "healthy"
            assert monitor.consecutive_failures == 1

    def test_crash_after_threshold_raises(self):
        """Repeated failures past the threshold raise BoofuzzFailure."""
        from boofuzz.exception import BoofuzzFailure

        with patch("socket.socket"), patch("ssl.create_default_context") as mock_ctx:
            secure_sock = MagicMock()
            secure_sock.connect.side_effect = OSError("Connection refused")
            mock_ctx.return_value.wrap_socket.return_value = secure_sock

            monitor = _make_ssl_monitor(retry_count=1, failure_threshold=1)
            with pytest.raises(BoofuzzFailure):
                monitor._check_alive(Mock())


class TestCustomSSLSocketMonitorProbeRuns:
    """Regression guard for the inverted rate-limit gate (finding #4)."""

    def test_probe_actually_runs_across_pre_post_cycle(self):
        """pre_send+post_send must actually contact the target at least once.

        The old gate set last_check_time in pre_send and then short-circuited
        post_send on (now - last_check_time < check_interval), so the TLS probe
        never ran and a crashed target was reported healthy. This asserts the
        handshake is attempted during a normal send cycle.
        """
        with patch("socket.socket"), patch("ssl.create_default_context") as mock_ctx:
            secure_sock = MagicMock()
            mock_ctx.return_value.wrap_socket.return_value = secure_sock

            monitor = _make_ssl_monitor("192.168.1.1", 8443)
            monitor.pre_send(target=Mock(), fuzz_data_logger=Mock())
            monitor.post_send(target=Mock(), fuzz_data_logger=Mock())

            # Old broken code: 0 connects. Fixed code: at least one real probe.
            assert secure_sock.connect.call_count >= 1

    def test_post_send_alone_probes(self):
        """A fresh monitor's post_send runs the probe (no pre_send timer reset)."""
        with patch("socket.socket"), patch("ssl.create_default_context") as mock_ctx:
            secure_sock = MagicMock()
            mock_ctx.return_value.wrap_socket.return_value = secure_sock

            monitor = _make_ssl_monitor("192.168.1.1", 8443)
            result = monitor.post_send(target=Mock(), fuzz_data_logger=Mock())

            assert result is True
            secure_sock.connect.assert_called_with(("192.168.1.1", 8443))


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
