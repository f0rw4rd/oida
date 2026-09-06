"""Base connection classes and abstract factory for protocol fuzzing."""

from abc import ABC, abstractmethod
from ..config import FuzzerConfig


class BaseConnection(ABC):
    """Abstract base class for connections."""

    @abstractmethod
    def send(self, data: bytes) -> int:
        """Send data."""

    @abstractmethod
    def recv(self, max_bytes: int = 1024) -> bytes:
        """Receive data."""

    @abstractmethod
    def close(self):
        """Close connection."""


class ConnectionFactory(ABC):
    """Abstract factory for creating network connections"""

    @abstractmethod
    def create_connection(self, config: FuzzerConfig):
        pass


class MockConnection:
    """Mock connection for testing"""

    def __init__(self):
        self.sent_data = []
        self.recv_data = b""  # Single response data
        self.response_queue = []  # Queue of responses for multi-response scenarios
        self.is_open = True  # Auto-open for simplicity
        self.host = None
        self.port = None

    def open(self):
        self.is_open = True

    def close(self):
        self.is_open = False

    def send(self, data: bytes):
        if not self.is_open:
            raise ConnectionError("Connection not open")
        self.sent_data.append(data)
        return len(data)

    def recv(self, max_bytes: int = 1024) -> bytes:
        if not self.is_open:
            raise ConnectionError("Connection not open")
        # Use queued response if available, otherwise use default recv_data
        if self.response_queue:
            return self.response_queue.pop(0)
        return self.recv_data

    def add_response(self, data: bytes):
        """Add a response to the response queue"""
        self.response_queue.append(data)


class MockConnectionFactory(ConnectionFactory):
    """Mock connection factory for testing"""

    def __init__(self):
        self.created_connections = []
        self.should_fail = False

    def create_connection(self, host_or_config, port=None, proto="tcp") -> MockConnection:
        """Create a mock connection.

        Args:
            host_or_config: Either a FuzzerConfig object or a hostname/IP string
            port: Port number (only used if host_or_config is a string)
            proto: Protocol type (ignored for mocks)

        Returns:
            MockConnection object or None if should_fail is True
        """
        if self.should_fail:
            return None

        mock_conn = MockConnection()

        # Support both FuzzerConfig and simple parameters
        if isinstance(host_or_config, str):
            mock_conn.host = host_or_config
            mock_conn.port = port
        else:
            # FuzzerConfig mode
            config = host_or_config
            mock_conn.host = config.target_ip
            mock_conn.port = config.target_port

        self.created_connections.append(mock_conn)
        return mock_conn

    def get_last_connection(self) -> MockConnection:
        """Get the most recently created connection for testing"""
        return self.created_connections[-1] if self.created_connections else None
