"""Tests for oida.utils.rate_limiter module."""

import socket
import threading
import time
from unittest.mock import MagicMock, patch


from oida.utils.rate_limiter import (
    RateLimiter,
    get_rate_limiter,
    rate_limit,
    scapy_sendp,
    scapy_srp,
    send_packet,
    sendto,
    set_rate_limit,
)


class TestRateLimiter:
    """Tests for RateLimiter class."""

    def test_init_default_rate(self):
        """Test default rate of 10 pps."""
        limiter = RateLimiter()
        assert limiter.packets_per_second == 10.0
        assert limiter.interval == 0.1  # 100ms

    def test_init_custom_rate(self):
        """Test custom rate."""
        limiter = RateLimiter(packets_per_second=20.0)
        assert limiter.packets_per_second == 20.0
        assert limiter.interval == 0.05  # 50ms

    def test_init_zero_rate_unlimited(self):
        """Test zero rate means unlimited."""
        limiter = RateLimiter(packets_per_second=0)
        assert limiter.interval == 0

    def test_wait_timing(self):
        """Test that wait() enforces timing."""
        limiter = RateLimiter(packets_per_second=20.0)  # 50ms interval

        start = time.time()
        for _ in range(5):
            limiter.wait()
        elapsed = time.time() - start

        # 5 packets at 20 pps = 4 intervals of 50ms = 200ms
        assert 0.18 <= elapsed <= 0.30  # Allow some tolerance

    def test_wait_unlimited_no_delay(self):
        """Test that unlimited rate has no delay."""
        limiter = RateLimiter(packets_per_second=0)

        start = time.time()
        for _ in range(100):
            limiter.wait()
        elapsed = time.time() - start

        assert elapsed < 0.1  # Should be nearly instant

    def test_packet_count_tracking(self):
        """Test packet count is tracked."""
        limiter = RateLimiter(packets_per_second=100.0)  # Fast for testing
        assert limiter.packet_count == 0

        for _ in range(10):
            limiter.wait()

        assert limiter.packet_count == 10

    def test_reset(self):
        """Test reset clears state."""
        limiter = RateLimiter(packets_per_second=100.0)
        for _ in range(5):
            limiter.wait()

        assert limiter.packet_count == 5

        limiter.reset()
        assert limiter.packet_count == 0
        assert limiter.last_send == 0.0

    def test_repr(self):
        """Test string representation."""
        limiter = RateLimiter(packets_per_second=10.0)
        for _ in range(3):
            limiter.wait()

        repr_str = repr(limiter)
        assert "RateLimiter" in repr_str
        assert "pps=10.0" in repr_str
        assert "sent=3" in repr_str

    def test_thread_safety(self):
        """Test that rate limiting works across threads."""
        limiter = RateLimiter(packets_per_second=50.0)  # 20ms interval
        results = []

        def worker():
            for _ in range(5):
                limiter.wait()
                results.append(time.time())

        threads = [threading.Thread(target=worker) for _ in range(3)]
        start = time.time()

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        elapsed = time.time() - start

        # 3 threads x 5 packets = 15 packets total
        # At 50 pps, 15 packets = 14 intervals of 20ms = 280ms minimum
        assert limiter.packet_count == 15
        assert elapsed >= 0.25  # At least 280ms - some tolerance


class TestGlobalRateLimiter:
    """Tests for global rate limiter functions."""

    def teardown_method(self):
        """Reset global rate limiter after each test."""
        set_rate_limit(0)

    def test_set_rate_limit_enabled(self):
        """Test enabling rate limit."""
        limiter = set_rate_limit(10.0)
        assert limiter is not None
        assert limiter.packets_per_second == 10.0

    def test_set_rate_limit_disabled(self):
        """Test disabling rate limit."""
        set_rate_limit(10.0)  # Enable first
        limiter = set_rate_limit(0)
        assert limiter is None

    def test_set_rate_limit_negative_disabled(self):
        """Test negative rate disables limiting."""
        limiter = set_rate_limit(-5.0)
        assert limiter is None

    def test_get_rate_limiter(self):
        """Test getting current rate limiter."""
        assert get_rate_limiter() is None

        set_rate_limit(10.0)
        limiter = get_rate_limiter()
        assert limiter is not None
        assert limiter.packets_per_second == 10.0

    def test_rate_limit_function(self):
        """Test rate_limit() applies limiting when enabled."""
        set_rate_limit(50.0)  # 20ms interval

        start = time.time()
        for _ in range(5):
            rate_limit()
        elapsed = time.time() - start

        # 5 calls at 50 pps = 4 intervals = 80ms
        assert 0.07 <= elapsed <= 0.15

    def test_rate_limit_function_disabled(self):
        """Test rate_limit() does nothing when disabled."""
        set_rate_limit(0)

        start = time.time()
        for _ in range(100):
            rate_limit()
        elapsed = time.time() - start

        assert elapsed < 0.05  # Nearly instant


class TestSendtoWrapper:
    """Tests for sendto() wrapper."""

    def teardown_method(self):
        """Reset global rate limiter after each test."""
        set_rate_limit(0)

    def test_sendto_calls_socket(self):
        """Test sendto passes through to socket."""
        mock_sock = MagicMock(spec=socket.socket)
        mock_sock.sendto.return_value = 10

        result = sendto(mock_sock, b"data", ("127.0.0.1", 1234))

        mock_sock.sendto.assert_called_once_with(b"data", ("127.0.0.1", 1234))
        assert result == 10

    def test_sendto_applies_rate_limit(self):
        """Test sendto applies rate limiting."""
        set_rate_limit(20.0)  # 50ms interval
        mock_sock = MagicMock(spec=socket.socket)
        mock_sock.sendto.return_value = 5

        start = time.time()
        for _ in range(5):
            sendto(mock_sock, b"test", ("127.0.0.1", 80))
        elapsed = time.time() - start

        assert mock_sock.sendto.call_count == 5
        assert elapsed >= 0.15  # At least 4 * 50ms


class TestSendPacketWrapper:
    """Tests for send_packet() wrapper."""

    def teardown_method(self):
        """Reset global rate limiter after each test."""
        set_rate_limit(0)

    def test_send_packet_with_address(self):
        """Test send_packet with address (UDP-style)."""
        mock_sock = MagicMock(spec=socket.socket)
        mock_sock.sendto.return_value = 10

        result = send_packet(mock_sock, b"data", ("127.0.0.1", 1234))

        mock_sock.sendto.assert_called_once_with(b"data", ("127.0.0.1", 1234))
        assert result == 10

    def test_send_packet_without_address(self):
        """Test send_packet without address (connected socket)."""
        mock_sock = MagicMock(spec=socket.socket)
        mock_sock.send.return_value = 10

        result = send_packet(mock_sock, b"data")

        mock_sock.send.assert_called_once_with(b"data")
        assert result == 10


class TestScapySendpWrapper:
    """Tests for scapy_sendp() wrapper."""

    def teardown_method(self):
        """Reset global rate limiter after each test."""
        set_rate_limit(0)

    @patch("scapy.all.sendp")
    def test_scapy_sendp_passthrough(self, mock_sendp):
        """Test scapy_sendp passes through to sendp."""
        mock_pkt = MagicMock()
        mock_sendp.return_value = None

        scapy_sendp(mock_pkt, iface="eth0", verbose=0)

        mock_sendp.assert_called_once_with(mock_pkt, iface="eth0", verbose=0)

    @patch("scapy.all.sendp")
    def test_scapy_sendp_applies_rate_limit(self, mock_sendp):
        """Test scapy_sendp applies rate limiting."""
        set_rate_limit(20.0)
        mock_pkt = MagicMock()

        start = time.time()
        for _ in range(5):
            scapy_sendp(mock_pkt, iface="eth0")
        elapsed = time.time() - start

        assert mock_sendp.call_count == 5
        assert elapsed >= 0.15


class TestScapySrpWrapper:
    """Tests for scapy_srp() wrapper."""

    def teardown_method(self):
        """Reset global rate limiter after each test."""
        set_rate_limit(0)

    @patch("scapy.all.srp")
    def test_scapy_srp_passthrough(self, mock_srp):
        """Test scapy_srp passes through to srp."""
        mock_pkt = MagicMock()
        mock_srp.return_value = ([], [])

        result = scapy_srp(mock_pkt, iface="eth0", timeout=2, verbose=0)

        mock_srp.assert_called_once_with(mock_pkt, iface="eth0", timeout=2, verbose=0)
        assert result == ([], [])

    @patch("scapy.all.srp")
    def test_scapy_srp_sets_inter_when_rate_limited(self, mock_srp):
        """Test scapy_srp sets inter parameter when rate limiting enabled."""
        set_rate_limit(10.0)  # 100ms interval
        mock_pkt = MagicMock()
        mock_srp.return_value = ([], [])

        scapy_srp(mock_pkt, iface="eth0", timeout=2)

        # inter should be set to 0.1 (100ms)
        call_kwargs = mock_srp.call_args[1]
        assert call_kwargs.get("inter") == 0.1

    @patch("scapy.all.srp")
    def test_scapy_srp_respects_existing_inter(self, mock_srp):
        """Test scapy_srp doesn't override explicit inter parameter."""
        set_rate_limit(10.0)
        mock_pkt = MagicMock()
        mock_srp.return_value = ([], [])

        scapy_srp(mock_pkt, iface="eth0", inter=0.5)

        call_kwargs = mock_srp.call_args[1]
        assert call_kwargs.get("inter") == 0.5

    @patch("scapy.all.srp")
    def test_scapy_srp_no_inter_when_unlimited(self, mock_srp):
        """Test scapy_srp doesn't set inter when rate limiting disabled."""
        set_rate_limit(0)
        mock_pkt = MagicMock()
        mock_srp.return_value = ([], [])

        scapy_srp(mock_pkt, iface="eth0", timeout=2)

        call_kwargs = mock_srp.call_args[1]
        assert "inter" not in call_kwargs
