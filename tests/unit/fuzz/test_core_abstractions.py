"""
Basic tests for fuzz core abstractions.
These tests don't require boofuzz dependency.
"""

import pytest
from unittest.mock import Mock


class TestConnectionFactory:
    """Test connection factory without boofuzz"""

    def test_mock_connection_factory_creates_connections(self):
        """Test MockConnectionFactory creates connections."""
        from oida.fuzz.core.connections import MockConnectionFactory, MockConnection

        factory = MockConnectionFactory()

        # Mock config object
        config = Mock()
        config.target_ip = "192.168.1.1"
        config.target_port = 80

        connection = factory.create_connection(config)

        assert isinstance(connection, MockConnection)
        assert connection.host == "192.168.1.1"
        assert connection.port == 80
        assert len(factory.created_connections) == 1

    def test_mock_connection_behavior(self):
        """Test mock connection behavior"""
        from oida.fuzz.core.connections import MockConnection

        conn = MockConnection()
        conn.add_response(b"HTTP/1.1 200 OK\r\n\r\n")

        conn.open()
        assert conn.is_open

        sent_bytes = conn.send(b"GET / HTTP/1.1\r\n\r\n")
        assert sent_bytes == 18
        assert conn.sent_data == [b"GET / HTTP/1.1\r\n\r\n"]

        response = conn.recv(1024)
        assert response == b"HTTP/1.1 200 OK\r\n\r\n"


class TestDatabaseInterface:
    """Test database abstraction with lightweight storage model"""

    def test_mock_database_stores_test_cases(self):
        """Test MockDatabase can store and retrieve test cases."""
        from oida.fuzz.core.database import MockDatabase, TestCase

        db = MockDatabase()
        db.init_schema()

        # Add test case metadata (lightweight storage)
        test_case = TestCase(
            id=1, name="test_case", timestamp="2023-01-01", result="pass", crc32=0x12345678
        )
        db.store_test_case(test_case)

        # Test retrieval
        cases = db.get_test_cases()
        assert len(cases) == 1
        assert cases[0].name == "test_case"

        # Test get specific test case
        retrieved = db.get_test_case(1)
        assert retrieved is not None
        assert retrieved.name == "test_case"
        assert retrieved.crc32 == 0x12345678

    def test_mock_database_stores_crashes(self):
        """Test MockDatabase can store and retrieve crashes."""
        from oida.fuzz.core.database import MockDatabase, TestCase, Crash

        db = MockDatabase()
        db.init_schema()

        # Add a crash with full payload
        crash_case = TestCase(
            id=2, name="crash_case", timestamp="2023-01-01", result="crash", crc32=0xDEADBEEF
        )
        db.store_test_case(crash_case)
        crash = Crash(
            test_case_id=2, payload=b"GET /crash HTTP/1.1", crash_info="Segmentation fault"
        )
        db.store_crash(crash)

        # Test crash retrieval
        retrieved_crash = db.get_crash(2)
        assert retrieved_crash is not None
        assert retrieved_crash.payload == b"GET /crash HTTP/1.1"
        assert retrieved_crash.crash_info == "Segmentation fault"

    def test_mock_database_stats(self):
        """Test MockDatabase computes stats correctly."""
        from oida.fuzz.core.database import MockDatabase, TestCase

        db = MockDatabase()
        db.init_schema()

        db.store_test_case(
            TestCase(id=1, name="pass1", timestamp="2023-01-01", result="pass", crc32=0x1)
        )
        db.store_test_case(
            TestCase(id=2, name="crash1", timestamp="2023-01-01", result="crash", crc32=0x2)
        )
        db.store_test_case(
            TestCase(id=3, name="fail1", timestamp="2023-01-01", result="fail", crc32=0x3)
        )

        stats = db.get_stats()
        assert stats["total_test_cases"] == 3
        assert stats["crashed"] == 1
        assert stats["passed"] == 1
        assert stats["failed"] == 1


class TestFuzzerConfig:
    """Test FuzzerConfig dataclass"""

    def test_config_defaults(self):
        """Test FuzzerConfig default values."""
        from oida.fuzz.core.config import FuzzerConfig

        config = FuzzerConfig(target_ip="192.168.1.1", target_port=502)

        assert config.target_ip == "192.168.1.1"
        assert config.target_port == 502
        assert config.session_filename == "fuzzer_session"
        assert config.log_session is True
        assert config.console_output is False  # Default is False for cleaner output

    def test_config_with_options(self):
        """Test FuzzerConfig with custom options."""
        from oida.fuzz.core.config import FuzzerConfig

        config = FuzzerConfig(
            target_ip="10.0.0.1",
            target_port=80,
            session_filename="http_test",
            log_session=False,
            protocol_options={"timeout": 5},
        )

        assert config.target_ip == "10.0.0.1"
        assert config.target_port == 80
        assert config.session_filename == "http_test"
        assert config.log_session is False
        assert config.get_option("timeout") == 5
        assert config.get_option("missing", "default") == "default"


class TestProtocolType:
    """Test ProtocolType enum"""

    def test_protocol_types(self):
        """Test ProtocolType enum values."""
        from oida.fuzz.core.config import ProtocolType

        assert ProtocolType.TCP.value == "tcp"
        assert ProtocolType.UDP.value == "udp"
        assert ProtocolType.SSL.value == "ssl"


class TestRequestInfo:
    """Test RequestInfo dataclass"""

    def test_request_info_creation(self):
        """Test RequestInfo creation."""
        from oida.fuzz.core.base_fuzzer import RequestInfo

        info = RequestInfo(name="HTTP_GET", description="HTTP GET request", category="baseline")

        assert info.name == "HTTP_GET"
        assert info.description == "HTTP GET request"
        assert info.category == "baseline"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
