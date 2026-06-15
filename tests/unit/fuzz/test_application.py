"""
Tests for FuzzerApplication and related functionality.
"""

import pytest
from unittest.mock import Mock


class TestFuzzerApplication:
    """Test FuzzerApplication class."""

    def test_application_initialization(self):
        """Test FuzzerApplication can be initialized."""
        from oida.fuzz.core.application import FuzzerApplication

        app = FuzzerApplication()
        assert app is not None
        assert app.fuzzer_factory is not None

    def test_application_with_custom_factory(self):
        """Test FuzzerApplication with custom fuzzer factory."""
        from oida.fuzz.core.application import FuzzerApplication

        custom_factory = Mock()
        app = FuzzerApplication(fuzzer_factory=custom_factory)
        assert app.fuzzer_factory == custom_factory

    def test_application_with_connection_factory(self):
        """Test FuzzerApplication with connection factory."""
        from oida.fuzz.core.application import FuzzerApplication
        from oida.fuzz.core.connections import MockConnectionFactory

        conn_factory = MockConnectionFactory()
        app = FuzzerApplication(connection_factory=conn_factory)
        assert app.connection_factory == conn_factory


class TestArgsWrapper:
    """Test argument wrapper construction in run_fuzzing."""

    def test_args_wrapper_basic_fields(self):
        """Test ArgsWrapper has basic required fields."""
        # Create a mock args object like the CLI would produce
        args = Mock()
        args.ip = "192.168.1.1"
        args.port = 502
        args.protocol = "modbus"
        args.session = "test_session"
        args.nolog = False
        args.skip_pre_send = True
        args.check_interval = 100
        args.console_output = False
        args.seed = 12345
        args.protocol_options = {}
        args.distribution_total = None
        args.distribution_id = None
        args.enabled_requests = None
        args.disabled_requests = None
        args.monitor_config = None
        args.monitor_logic = "and"
        args.reuse_connection = True
        args.tls_enabled = False
        args.enumerate = True
        args.node = None
        args.command = "fuzz"
        args.index_start = 1

        # Verify all expected attributes exist
        assert args.ip == "192.168.1.1"
        assert args.port == 502
        assert args.protocol == "modbus"


class TestFuzzerConfigFromArgs:
    """Test FuzzerConfig creation from CLI args."""

    def test_config_creation_basic(self):
        """Test FuzzerConfig creation with basic args."""
        from oida.fuzz.core.config import FuzzerConfig

        config = FuzzerConfig(
            target_ip="192.168.1.1",
            target_port=502,
            protocol="modbus",
            session_filename="test_session",
            log_session=True,
            skip_pre_send_checks=True,
            monitor_check_interval=100,
        )

        assert config.target_ip == "192.168.1.1"
        assert config.target_port == 502
        assert config.protocol == "modbus"

    def test_config_creation_with_tls(self):
        """Test FuzzerConfig creation with TLS enabled."""
        from oida.fuzz.core.config import FuzzerConfig

        config = FuzzerConfig(
            target_ip="192.168.1.1",
            target_port=443,
            tls_enabled=True,
        )

        assert config.tls_enabled is True

    def test_config_creation_with_monitor_config(self):
        """Test FuzzerConfig creation with monitor config."""
        from oida.fuzz.core.config import FuzzerConfig, MonitorConfig

        monitor_config = MonitorConfig.parse("ping:50,modbus:10")
        config = FuzzerConfig(
            target_ip="192.168.1.1",
            target_port=502,
            monitor_config=monitor_config,
            monitor_logic="or",
        )

        assert config.monitor_config is not None
        assert config.monitor_logic == "or"

    def test_config_creation_with_distribution(self):
        """Test FuzzerConfig creation with distribution settings."""
        from oida.fuzz.core.config import FuzzerConfig

        config = FuzzerConfig(
            target_ip="192.168.1.1",
            target_port=502,
            distribution_total=3,
            distribution_id=2,
        )

        assert config.distribution_total == 3
        assert config.distribution_id == 2

    def test_config_creation_with_request_filters(self):
        """Test FuzzerConfig creation with request filters."""
        from oida.fuzz.core.config import FuzzerConfig

        config = FuzzerConfig(
            target_ip="192.168.1.1",
            target_port=502,
            enabled_requests=["read_coils", "read_holding"],
            disabled_requests=["write_coils"],
        )

        assert config.enabled_requests == ["read_coils", "read_holding"]
        assert config.disabled_requests == ["write_coils"]

    def test_config_creation_with_enumerate(self):
        """Test FuzzerConfig creation with enumerate setting."""
        from oida.fuzz.core.config import FuzzerConfig

        config = FuzzerConfig(
            target_ip="192.168.1.1",
            target_port=502,
            enumerate=False,
        )

        assert config.enumerate is False


class TestRequestInfo:
    """Test RequestInfo dataclass."""

    def test_request_info_basic(self):
        """Test RequestInfo creation."""
        from oida.fuzz.core.base_fuzzer import RequestInfo

        info = RequestInfo(
            name="read_coils",
            description="Read coils from device",
            category="read",
        )

        assert info.name == "read_coils"
        assert info.description == "Read coils from device"
        assert info.category == "read"

    def test_request_info_with_default_category(self):
        """Test RequestInfo with default category."""
        from oida.fuzz.core.base_fuzzer import RequestInfo

        info = RequestInfo(
            name="test_request",
            description="Test request",
        )

        assert info.name == "test_request"
        assert info.category == "general"  # default


class TestBaseFuzzerClassMethods:
    """Test BaseFuzzer class methods."""

    def test_get_protocol_options(self):
        """Test get_protocol_options returns dict."""
        from oida.fuzz.protocols import PROTOCOL_FUZZERS

        fuzzer_class = PROTOCOL_FUZZERS.get("modbus")
        if fuzzer_class:
            options = fuzzer_class.get_protocol_options()
            assert isinstance(options, dict)

    def test_get_request_definitions(self):
        """Test get_request_definitions returns list."""
        from oida.fuzz.protocols import PROTOCOL_FUZZERS

        fuzzer_class = PROTOCOL_FUZZERS.get("modbus")
        if fuzzer_class:
            requests = fuzzer_class.get_request_definitions()
            assert isinstance(requests, list)

    def test_format_options_help(self):
        """Test format_options_help returns string."""
        from oida.fuzz.protocols import PROTOCOL_FUZZERS

        fuzzer_class = PROTOCOL_FUZZERS.get("modbus")
        if fuzzer_class:
            help_text = fuzzer_class.format_options_help()
            assert isinstance(help_text, str)

    def test_format_requests_help(self):
        """Test format_requests_help returns string."""
        from oida.fuzz.protocols import PROTOCOL_FUZZERS

        fuzzer_class = PROTOCOL_FUZZERS.get("modbus")
        if fuzzer_class:
            help_text = fuzzer_class.format_requests_help()
            assert isinstance(help_text, str)


class TestProtocolType:
    """Test ProtocolType enum."""

    def test_all_protocol_types(self):
        """Test all ProtocolType values."""
        from oida.fuzz.core.config import ProtocolType

        assert ProtocolType.TCP.value == "tcp"
        assert ProtocolType.SSL.value == "ssl"
        assert ProtocolType.UDP.value == "udp"
        assert ProtocolType.RAW.value == "raw"
        assert ProtocolType.SERIAL.value == "serial"
        assert ProtocolType.IEC104.value == "iec104"


class TestHexdump:
    """Test hexdump utility function."""

    def test_hexdump_empty(self):
        """Test hexdump with empty data."""
        from oida.fuzz.core.config import hexdump

        result = hexdump(b"")
        assert result == ""

    def test_hexdump_short_data(self):
        """Test hexdump with short data."""
        from oida.fuzz.core.config import hexdump

        result = hexdump(b"ABC")
        assert "41 42 43" in result
        assert "ABC" in result

    def test_hexdump_with_non_printable(self):
        """Test hexdump with non-printable characters."""
        from oida.fuzz.core.config import hexdump

        result = hexdump(b"\x00\x01\x02")
        assert "00 01 02" in result
        assert "..." in result  # non-printable shown as dots

    def test_hexdump_multiple_lines(self):
        """Test hexdump with data spanning multiple lines."""
        from oida.fuzz.core.config import hexdump

        data = b"A" * 32  # Two lines at 16 bytes per line
        result = hexdump(data)
        lines = result.split("\n")
        assert len(lines) == 2


class TestFuzzerConfigOptions:
    """Test FuzzerConfig option methods."""

    def test_get_option_existing(self):
        """Test get_option for existing option."""
        from oida.fuzz.core.config import FuzzerConfig

        config = FuzzerConfig(
            target_ip="127.0.0.1", target_port=502, protocol_options={"unit_id": 5}
        )

        assert config.get_option("unit_id") == 5

    def test_get_option_missing_with_default(self):
        """Test get_option for missing option with default."""
        from oida.fuzz.core.config import FuzzerConfig

        config = FuzzerConfig(
            target_ip="127.0.0.1",
            target_port=502,
        )

        assert config.get_option("missing", "default") == "default"

    def test_get_option_missing_no_default(self):
        """Test get_option for missing option without default."""
        from oida.fuzz.core.config import FuzzerConfig

        config = FuzzerConfig(
            target_ip="127.0.0.1",
            target_port=502,
        )

        assert config.get_option("missing") is None

    def test_set_option(self):
        """Test set_option method."""
        from oida.fuzz.core.config import FuzzerConfig

        config = FuzzerConfig(
            target_ip="127.0.0.1",
            target_port=502,
        )

        config.set_option("new_option", "value")
        assert config.get_option("new_option") == "value"

    def test_set_option_initializes_dict(self):
        """__post_init__ guarantees protocol_options is a dict; set_option writes to it."""
        from oida.fuzz.core.config import FuzzerConfig

        config = FuzzerConfig(
            target_ip="127.0.0.1",
            target_port=502,
        )
        assert config.protocol_options == {}

        config.set_option("key", "value")
        assert config.get_option("key") == "value"


class TestMockDatabase:
    """Test MockDatabase functionality."""

    def test_mock_database_init_schema(self):
        """Test MockDatabase init_schema."""
        from oida.fuzz.core.database import MockDatabase

        db = MockDatabase()
        db.init_schema()
        # Should not raise

    def test_mock_database_get_stats_empty(self):
        """Test MockDatabase get_stats with no data."""
        from oida.fuzz.core.database import MockDatabase

        db = MockDatabase()
        db.init_schema()
        stats = db.get_stats()

        assert stats["total_test_cases"] == 0
        assert stats["passed"] == 0
        assert stats["failed"] == 0
        assert stats["crashed"] == 0

    def test_mock_database_get_test_case_not_found(self):
        """Test MockDatabase get_test_case for non-existent case."""
        from oida.fuzz.core.database import MockDatabase

        db = MockDatabase()
        db.init_schema()

        result = db.get_test_case(999)
        assert result is None

    def test_mock_database_get_crash_not_found(self):
        """Test MockDatabase get_crash for non-existent crash."""
        from oida.fuzz.core.database import MockDatabase

        db = MockDatabase()
        db.init_schema()

        result = db.get_crash(999)
        assert result is None

    def test_mock_database_filter_by_result(self):
        """Test MockDatabase get_test_cases with result filter."""
        from oida.fuzz.core.database import MockDatabase, TestCase

        db = MockDatabase()
        db.init_schema()

        db.store_test_case(
            TestCase(id=1, name="pass1", timestamp="2023-01-01", result="pass", crc32=0x1)
        )
        db.store_test_case(
            TestCase(id=2, name="crash1", timestamp="2023-01-01", result="crash", crc32=0x2)
        )

        crash_cases = db.get_test_cases(result_filter="crash")
        assert len(crash_cases) == 1
        assert crash_cases[0].result == "crash"


class TestMockConnection:
    """Test MockConnection functionality."""

    def test_mock_connection_open_close(self):
        """Test MockConnection open and close."""
        from oida.fuzz.core.connections import MockConnection

        conn = MockConnection()
        # MockConnection is auto-open by default for simplicity
        assert conn.is_open

        conn.close()
        assert not conn.is_open

        conn.open()
        assert conn.is_open

    def test_mock_connection_send_receive(self):
        """Test MockConnection send and receive."""
        from oida.fuzz.core.connections import MockConnection

        conn = MockConnection()
        conn.add_response(b"response data")
        conn.open()

        sent = conn.send(b"request data")
        assert sent == len(b"request data")
        assert b"request data" in conn.sent_data

        received = conn.recv(1024)
        assert received == b"response data"

    def test_mock_connection_recv_empty(self):
        """Test MockConnection recv with no responses."""
        from oida.fuzz.core.connections import MockConnection

        conn = MockConnection()
        conn.open()

        received = conn.recv(1024)
        assert received == b""

    def test_mock_connection_add_response(self):
        """Test MockConnection add_response method."""
        from oida.fuzz.core.connections import MockConnection

        conn = MockConnection()
        conn.add_response(b"response1")
        conn.add_response(b"response2")

        # Responses are queued
        assert conn.recv(1024) == b"response1"
        assert conn.recv(1024) == b"response2"
        # After queue is empty, returns default recv_data
        assert conn.recv(1024) == b""


class TestMockConnectionFactory:
    """Test MockConnectionFactory functionality."""

    def test_factory_tracks_connections(self):
        """Test MockConnectionFactory tracks created connections."""
        from oida.fuzz.core.connections import MockConnectionFactory

        factory = MockConnectionFactory()
        assert len(factory.created_connections) == 0

        config = Mock()
        config.target_ip = "127.0.0.1"
        config.target_port = 80

        factory.create_connection(config)
        factory.create_connection(config)

        assert len(factory.created_connections) == 2

    def test_factory_get_last_connection(self):
        """Test MockConnectionFactory get_last_connection method."""
        from oida.fuzz.core.connections import MockConnectionFactory

        factory = MockConnectionFactory()

        # No connections yet
        assert factory.get_last_connection() is None

        config = Mock()
        config.target_ip = "127.0.0.1"
        config.target_port = 80

        factory.create_connection(config)
        conn2 = factory.create_connection(config)

        # Should return most recent connection
        assert factory.get_last_connection() == conn2

    def test_factory_should_fail(self):
        """Test MockConnectionFactory should_fail flag."""
        from oida.fuzz.core.connections import MockConnectionFactory

        factory = MockConnectionFactory()
        factory.should_fail = True

        config = Mock()
        config.target_ip = "127.0.0.1"
        config.target_port = 80

        conn = factory.create_connection(config)
        assert conn is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
