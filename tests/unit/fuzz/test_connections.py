"""
Tests for connection classes and factories.

Tests cover:
- BaseConnection: Abstract interface
- MockConnection: Test double for connections
- MockConnectionFactory: Test double for factory
- RealConnectionFactory: Production connection factory
- Connection lifecycle (open, send, recv, close)
"""

import pytest

from tests.service_gate import require_import


# =============================================================================
# Test BaseConnection Interface
# =============================================================================


class TestBaseConnectionInterface:
    """Tests for BaseConnection abstract class."""

    def test_cannot_instantiate_base_connection(self):
        """BaseConnection cannot be instantiated directly."""
        from src.oida.fuzz.core.connections.base import BaseConnection

        with pytest.raises(TypeError):
            BaseConnection()

    def test_base_connection_requires_send(self):
        """Subclass must implement send."""
        from src.oida.fuzz.core.connections.base import BaseConnection

        class IncompleteConnection(BaseConnection):
            def recv(self, max_bytes):
                pass

            def close(self):
                pass

        with pytest.raises(TypeError):
            IncompleteConnection()

    def test_base_connection_requires_recv(self):
        """Subclass must implement recv."""
        from src.oida.fuzz.core.connections.base import BaseConnection

        class IncompleteConnection(BaseConnection):
            def send(self, data):
                pass

            def close(self):
                pass

        with pytest.raises(TypeError):
            IncompleteConnection()


# =============================================================================
# Test MockConnection
# =============================================================================


class TestMockConnectionCreation:
    """Tests for MockConnection instantiation."""

    def test_basic_creation(self):
        """MockConnection can be created."""
        from src.oida.fuzz.core.connections.base import MockConnection

        conn = MockConnection()
        assert conn is not None

    def test_initial_state(self):
        """MockConnection starts in open state."""
        from src.oida.fuzz.core.connections.base import MockConnection

        conn = MockConnection()
        assert conn.is_open is True
        assert conn.sent_data == []


class TestMockConnectionOpenClose:
    """Tests for MockConnection open/close methods."""

    def test_open(self):
        """open() sets is_open to True."""
        from src.oida.fuzz.core.connections.base import MockConnection

        conn = MockConnection()
        conn.is_open = False
        conn.open()
        assert conn.is_open is True

    def test_close(self):
        """close() sets is_open to False."""
        from src.oida.fuzz.core.connections.base import MockConnection

        conn = MockConnection()
        conn.close()
        assert conn.is_open is False


class TestMockConnectionSend:
    """Tests for MockConnection send method."""

    def test_send_records_data(self):
        """send() records sent data."""
        from src.oida.fuzz.core.connections.base import MockConnection

        conn = MockConnection()
        conn.send(b"test data")
        assert conn.sent_data == [b"test data"]

    def test_send_returns_length(self):
        """send() returns number of bytes sent."""
        from src.oida.fuzz.core.connections.base import MockConnection

        conn = MockConnection()
        result = conn.send(b"12345")
        assert result == 5

    def test_send_multiple_records_all(self):
        """Multiple sends record all data."""
        from src.oida.fuzz.core.connections.base import MockConnection

        conn = MockConnection()
        conn.send(b"first")
        conn.send(b"second")
        conn.send(b"third")
        assert conn.sent_data == [b"first", b"second", b"third"]

    def test_send_when_closed_raises(self):
        """send() raises when connection closed."""
        from src.oida.fuzz.core.connections.base import MockConnection

        conn = MockConnection()
        conn.close()
        with pytest.raises(ConnectionError):
            conn.send(b"test")


class TestMockConnectionRecv:
    """Tests for MockConnection recv method."""

    def test_recv_default_empty(self):
        """recv() returns empty by default."""
        from src.oida.fuzz.core.connections.base import MockConnection

        conn = MockConnection()
        result = conn.recv(1024)
        assert result == b""

    def test_recv_returns_configured_data(self):
        """recv() returns configured recv_data."""
        from src.oida.fuzz.core.connections.base import MockConnection

        conn = MockConnection()
        conn.recv_data = b"configured response"
        result = conn.recv(1024)
        assert result == b"configured response"

    def test_recv_when_closed_raises(self):
        """recv() raises when connection closed."""
        from src.oida.fuzz.core.connections.base import MockConnection

        conn = MockConnection()
        conn.close()
        with pytest.raises(ConnectionError):
            conn.recv(1024)


class TestMockConnectionResponseQueue:
    """Tests for MockConnection response queue."""

    def test_add_response(self):
        """add_response() adds to queue."""
        from src.oida.fuzz.core.connections.base import MockConnection

        conn = MockConnection()
        conn.add_response(b"response1")
        assert conn.response_queue == [b"response1"]

    def test_recv_uses_queue_fifo(self):
        """recv() uses queue in FIFO order."""
        from src.oida.fuzz.core.connections.base import MockConnection

        conn = MockConnection()
        conn.add_response(b"first")
        conn.add_response(b"second")
        conn.add_response(b"third")

        assert conn.recv(1024) == b"first"
        assert conn.recv(1024) == b"second"
        assert conn.recv(1024) == b"third"

    def test_recv_falls_back_to_recv_data(self):
        """recv() falls back to recv_data when queue empty."""
        from src.oida.fuzz.core.connections.base import MockConnection

        conn = MockConnection()
        conn.add_response(b"queued")
        conn.recv_data = b"fallback"

        assert conn.recv(1024) == b"queued"  # From queue
        assert conn.recv(1024) == b"fallback"  # Queue empty, use recv_data


# =============================================================================
# Test MockConnectionFactory
# =============================================================================


class TestMockConnectionFactoryCreation:
    """Tests for MockConnectionFactory instantiation."""

    def test_basic_creation(self):
        """MockConnectionFactory can be created."""
        from src.oida.fuzz.core.connections.base import MockConnectionFactory

        factory = MockConnectionFactory()
        assert factory is not None
        assert factory.created_connections == []


class TestMockConnectionFactoryCreateConnection:
    """Tests for MockConnectionFactory create_connection method."""

    def test_create_connection_from_config(self):
        """create_connection() accepts FuzzerConfig."""
        from src.oida.fuzz.core.connections.base import MockConnectionFactory, MockConnection
        from src.oida.fuzz.core.config import FuzzerConfig

        factory = MockConnectionFactory()
        config = FuzzerConfig(target_ip="192.168.1.1", target_port=80)
        conn = factory.create_connection(config)

        assert isinstance(conn, MockConnection)
        assert conn.host == "192.168.1.1"
        assert conn.port == 80

    def test_create_connection_from_string(self):
        """create_connection() accepts host/port strings."""
        from src.oida.fuzz.core.connections.base import MockConnectionFactory, MockConnection

        factory = MockConnectionFactory()
        conn = factory.create_connection("10.0.0.1", 8080)

        assert isinstance(conn, MockConnection)
        assert conn.host == "10.0.0.1"
        assert conn.port == 8080

    def test_create_connection_tracks_created(self):
        """Factory tracks created connections."""
        from src.oida.fuzz.core.connections.base import MockConnectionFactory

        factory = MockConnectionFactory()
        factory.create_connection("host1", 80)
        factory.create_connection("host2", 443)

        assert len(factory.created_connections) == 2

    def test_should_fail_returns_none(self):
        """Factory returns None when should_fail is True."""
        from src.oida.fuzz.core.connections.base import MockConnectionFactory

        factory = MockConnectionFactory()
        factory.should_fail = True
        conn = factory.create_connection("192.168.1.1", 80)

        assert conn is None

    def test_get_last_connection(self):
        """get_last_connection() returns most recent."""
        from src.oida.fuzz.core.connections.base import MockConnectionFactory

        factory = MockConnectionFactory()
        factory.create_connection("first", 1)
        factory.create_connection("second", 2)
        factory.create_connection("third", 3)

        last = factory.get_last_connection()
        assert last.host == "third"
        assert last.port == 3

    def test_get_last_connection_empty(self):
        """get_last_connection() returns None when empty."""
        from src.oida.fuzz.core.connections.base import MockConnectionFactory

        factory = MockConnectionFactory()
        assert factory.get_last_connection() is None


# =============================================================================
# Test ConnectionFactory Interface
# =============================================================================


class TestConnectionFactoryInterface:
    """Tests for ConnectionFactory abstract class."""

    def test_cannot_instantiate_connection_factory(self):
        """ConnectionFactory cannot be instantiated directly."""
        from src.oida.fuzz.core.connections.base import ConnectionFactory

        with pytest.raises(TypeError):
            ConnectionFactory()


# =============================================================================
# Test RealConnectionFactory
# =============================================================================


class TestRealConnectionFactoryCreation:
    """Tests for RealConnectionFactory instantiation."""

    def test_basic_creation(self):
        """RealConnectionFactory can be created."""
        from src.oida.fuzz.core.connections.tcp import RealConnectionFactory

        factory = RealConnectionFactory()
        assert factory is not None


class TestRealConnectionFactoryTCP:
    """Tests for RealConnectionFactory TCP connection creation."""

    def test_create_tcp_connection_from_string(self):
        """create_connection() creates TCPSocketConnection."""
        from src.oida.fuzz.core.connections.tcp import RealConnectionFactory
        from boofuzz import TCPSocketConnection

        factory = RealConnectionFactory()
        conn = factory.create_connection("192.168.1.1", 80, proto="tcp")

        assert isinstance(conn, TCPSocketConnection)

    def test_create_tcp_connection_default(self):
        """TCP is the default protocol."""
        from src.oida.fuzz.core.connections.tcp import RealConnectionFactory
        from boofuzz import TCPSocketConnection

        factory = RealConnectionFactory()
        conn = factory.create_connection("192.168.1.1", 80)

        assert isinstance(conn, TCPSocketConnection)


class TestRealConnectionFactoryTimeouts:
    """Tests for socket timeout / reconnect overrides flowing from FuzzerConfig."""

    def test_overrides_applied_to_resilient_connection(self):
        """CLI overrides reach the reused (resilient) TCP connection."""
        from src.oida.fuzz.core.connections.tcp import (
            RealConnectionFactory,
            ResilientTCPConnection,
        )
        from src.oida.fuzz.core.config import FuzzerConfig

        config = FuzzerConfig(
            target_ip="127.0.0.1",
            target_port=502,
            reuse_target_connection=True,
            recv_timeout=0.5,
            send_timeout=0.7,
            reconnect_delay=0.1,
            max_reconnect_attempts=5,
        )
        conn = RealConnectionFactory().create_connection(config)

        assert isinstance(conn, ResilientTCPConnection)
        assert conn._recv_timeout == 0.5
        assert conn._send_timeout == 0.7
        assert conn.reconnect_delay == 0.1
        assert conn.max_reconnect_attempts == 5

    def test_defaults_retained_when_unset(self):
        """With no overrides (all None), the built-in defaults are kept."""
        from src.oida.fuzz.core.connections.tcp import RealConnectionFactory
        from src.oida.fuzz.core.config import FuzzerConfig

        config = FuzzerConfig(target_ip="127.0.0.1", target_port=502, reuse_target_connection=True)
        conn = RealConnectionFactory().create_connection(config)

        assert conn._recv_timeout == 5.0
        assert conn._send_timeout == 5.0
        assert conn.reconnect_delay == 0.5
        assert conn.max_reconnect_attempts == 3

    def test_overrides_applied_to_plain_tcp(self):
        """Overrides reach the non-reused plain TCP connection too."""
        from src.oida.fuzz.core.connections.tcp import RealConnectionFactory
        from src.oida.fuzz.core.config import FuzzerConfig

        config = FuzzerConfig(
            target_ip="127.0.0.1",
            target_port=502,
            reuse_target_connection=False,
            recv_timeout=0.5,
            send_timeout=0.7,
        )
        conn = RealConnectionFactory().create_connection(config)

        assert conn._recv_timeout == 0.5
        assert conn._send_timeout == 0.7

    def test_overrides_forwarded_to_iec104(self):
        """Regression: IEC104SocketConnection must forward socket timeouts to its base."""
        from src.oida.fuzz.core.connections.tcp import (
            RealConnectionFactory,
            IEC104SocketConnection,
        )
        from src.oida.fuzz.core.config import FuzzerConfig, ProtocolType

        config = FuzzerConfig(
            target_ip="127.0.0.1",
            target_port=2404,
            reuse_target_connection=True,
            protocol_type=ProtocolType.IEC104,
            recv_timeout=0.5,
            send_timeout=0.7,
            reconnect_delay=0.1,
            max_reconnect_attempts=5,
        )
        conn = RealConnectionFactory().create_connection(config)

        assert isinstance(conn, IEC104SocketConnection)
        assert conn._recv_timeout == 0.5
        assert conn._send_timeout == 0.7
        assert conn.reconnect_delay == 0.1
        assert conn.max_reconnect_attempts == 5


class TestRealConnectionFactoryUDP:
    """Tests for RealConnectionFactory UDP connection creation."""

    def test_create_udp_connection(self):
        """create_connection() creates UDPSocketConnection."""
        from src.oida.fuzz.core.connections.tcp import RealConnectionFactory
        from boofuzz import UDPSocketConnection

        factory = RealConnectionFactory()
        conn = factory.create_connection("192.168.1.1", 53, proto="udp")

        assert isinstance(conn, UDPSocketConnection)


class TestRealConnectionFactorySSL:
    """Tests for RealConnectionFactory SSL connection creation."""

    def test_create_ssl_connection(self):
        """create_connection() creates SSLSocketConnection."""
        from src.oida.fuzz.core.connections.tcp import RealConnectionFactory
        from boofuzz import SSLSocketConnection

        factory = RealConnectionFactory()
        conn = factory.create_connection("192.168.1.1", 443, proto="ssl")

        assert isinstance(conn, SSLSocketConnection)

    def test_create_tls_connection(self):
        """'tls' proto also creates SSLSocketConnection."""
        from src.oida.fuzz.core.connections.tcp import RealConnectionFactory
        from boofuzz import SSLSocketConnection

        factory = RealConnectionFactory()
        conn = factory.create_connection("192.168.1.1", 443, proto="tls")

        assert isinstance(conn, SSLSocketConnection)


class TestRealConnectionFactoryFromConfig:
    """Tests for RealConnectionFactory with FuzzerConfig."""

    def test_create_from_config_tcp(self):
        """create_connection() accepts FuzzerConfig for TCP."""
        from src.oida.fuzz.core.connections.tcp import RealConnectionFactory
        from src.oida.fuzz.core.config import FuzzerConfig, ProtocolType
        from boofuzz import TCPSocketConnection

        factory = RealConnectionFactory()
        config = FuzzerConfig(
            target_ip="192.168.1.1", target_port=80, protocol_type=ProtocolType.TCP
        )
        conn = factory.create_connection(config)

        assert isinstance(conn, TCPSocketConnection)

    def test_create_from_config_ssl(self):
        """create_connection() accepts FuzzerConfig for SSL."""
        from src.oida.fuzz.core.connections.tcp import RealConnectionFactory
        from src.oida.fuzz.core.config import FuzzerConfig, ProtocolType
        from boofuzz import SSLSocketConnection

        factory = RealConnectionFactory()
        config = FuzzerConfig(
            target_ip="192.168.1.1", target_port=443, protocol_type=ProtocolType.SSL
        )
        conn = factory.create_connection(config)

        assert isinstance(conn, SSLSocketConnection)

    def test_create_from_config_udp(self):
        """create_connection() accepts FuzzerConfig for UDP."""
        from src.oida.fuzz.core.connections.tcp import RealConnectionFactory
        from src.oida.fuzz.core.config import FuzzerConfig, ProtocolType
        from boofuzz import UDPSocketConnection

        factory = RealConnectionFactory()
        config = FuzzerConfig(
            target_ip="192.168.1.1", target_port=53, protocol_type=ProtocolType.UDP
        )
        conn = factory.create_connection(config)

        assert isinstance(conn, UDPSocketConnection)

    def test_create_from_config_tls_enabled_flag(self):
        """tls_enabled flag takes precedence."""
        from src.oida.fuzz.core.connections.tcp import RealConnectionFactory
        from src.oida.fuzz.core.config import FuzzerConfig, ProtocolType
        from boofuzz import SSLSocketConnection

        factory = RealConnectionFactory()
        config = FuzzerConfig(
            target_ip="192.168.1.1",
            target_port=80,
            protocol_type=ProtocolType.TCP,  # TCP but...
        )
        config.tls_enabled = True  # ...TLS flag overrides

        conn = factory.create_connection(config)

        assert isinstance(conn, SSLSocketConnection)


# =============================================================================
# Test Connection Lifecycle
# =============================================================================


class TestConnectionLifecycle:
    """Tests for connection lifecycle patterns."""

    def test_mock_connection_full_lifecycle(self):
        """Mock connection supports full lifecycle."""
        from src.oida.fuzz.core.connections.base import MockConnection

        conn = MockConnection()
        conn.add_response(b"HTTP/1.1 200 OK\r\n\r\n")

        # Open
        conn.open()
        assert conn.is_open

        # Send
        sent = conn.send(b"GET / HTTP/1.1\r\n\r\n")
        assert sent == 18

        # Receive
        response = conn.recv(1024)
        assert response == b"HTTP/1.1 200 OK\r\n\r\n"

        # Close
        conn.close()
        assert not conn.is_open

    def test_factory_connection_creation_pattern(self):
        """Factory follows common creation pattern."""
        from src.oida.fuzz.core.connections.base import MockConnectionFactory

        factory = MockConnectionFactory()

        # Create connection
        conn = factory.create_connection("192.168.1.1", 502)
        assert conn is not None

        # Configure response
        conn.add_response(b"\x00\x01\x00\x00\x00\x05\x01\x03\x02\x00\x00")

        # Use connection
        conn.send(b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x01")
        response = conn.recv(256)
        assert len(response) == 11


# =============================================================================
# Test Edge Cases
# =============================================================================


class TestConnectionEdgeCases:
    """Tests for edge cases in connections."""

    def test_empty_send(self):
        """send() handles empty data."""
        from src.oida.fuzz.core.connections.base import MockConnection

        conn = MockConnection()
        result = conn.send(b"")
        assert result == 0
        assert conn.sent_data == [b""]

    def test_large_send(self):
        """send() handles large data."""
        from src.oida.fuzz.core.connections.base import MockConnection

        conn = MockConnection()
        large_data = b"A" * 1000000  # 1MB
        result = conn.send(large_data)
        assert result == 1000000

    def test_multiple_open_close(self):
        """Connection handles multiple open/close cycles."""
        from src.oida.fuzz.core.connections.base import MockConnection

        conn = MockConnection()

        for _ in range(5):
            conn.open()
            assert conn.is_open
            conn.send(b"test")
            conn.close()
            assert not conn.is_open

    def test_host_port_attributes(self):
        """Connection stores host and port attributes."""
        from src.oida.fuzz.core.connections.base import MockConnectionFactory

        factory = MockConnectionFactory()
        conn = factory.create_connection("example.com", 8443)

        assert conn.host == "example.com"
        assert conn.port == 8443


class TestScapyRawConnectionProtocol:
    """Regression: the raw-socket TCP transport must set IP proto=TCP (6).

    A bare IP()/Raw(payload) leaves proto=0 (IPv6 nh=59), so the target drops
    every fuzz packet at IP demux while the run reports clean.
    """

    def _sent_packet(self, ipv6, data):
        scapy = require_import("scapy.all")
        scapy.conf.verb = 0
        from src.oida.fuzz.core.connections.scapy import ScapyRawConnection

        src = "::1" if ipv6 else "127.0.0.1"
        conn = ScapyRawConnection(host=src, port=80, source_ip=src, ipv6=ipv6)
        conn._init_scapy()
        captured = {}
        conn.scapy_send = lambda pkt, **kw: captured.setdefault("pkt", pkt)
        conn._sock = True
        conn.send(data)
        return captured["pkt"]

    def test_ipv4_full_segment_sets_proto_tcp(self):
        from scapy.all import TCP

        seg = bytes(TCP(sport=1234, dport=80, flags="S"))
        assert self._sent_packet(False, seg).proto == 6

    def test_ipv4_short_mutation_still_sets_proto_tcp(self):
        # A sub-header mutation must not fall back to proto=0.
        assert self._sent_packet(False, b"\x00\x01").proto == 6

    def test_ipv6_full_segment_sets_next_header_tcp(self):
        from scapy.all import TCP

        seg = bytes(TCP(sport=1234, dport=80, flags="S"))
        assert self._sent_packet(True, seg).nh == 6


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
