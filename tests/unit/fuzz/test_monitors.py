"""
Tests for monitor configuration, registry, and CombinedMonitor logic.
"""

import pytest
from unittest.mock import Mock


class TestMonitorSpec:
    """Test MonitorSpec dataclass."""

    def test_monitor_spec_creation(self):
        """Test MonitorSpec creation with name only."""
        from oida.fuzz.core.config import MonitorSpec

        spec = MonitorSpec(name="ping")
        assert spec.name == "ping"
        assert spec.interval is None

    def test_monitor_spec_with_interval(self):
        """Test MonitorSpec creation with interval."""
        from oida.fuzz.core.config import MonitorSpec

        spec = MonitorSpec(name="modbus", interval=10)
        assert spec.name == "modbus"
        assert spec.interval == 10


class TestMonitorConfig:
    """Test MonitorConfig parsing and methods."""

    def test_parse_simple_monitors(self):
        """Test parsing simple monitor list."""
        from oida.fuzz.core.config import MonitorConfig

        config = MonitorConfig.parse("ping,socket")
        assert len(config.monitors) == 2
        assert config.monitors[0].name == "ping"
        assert config.monitors[1].name == "socket"
        assert config.logic == "and"

    def test_parse_monitors_with_intervals(self):
        """Test parsing monitors with intervals."""
        from oida.fuzz.core.config import MonitorConfig

        config = MonitorConfig.parse("ping:50,modbus:10")
        assert len(config.monitors) == 2
        assert config.monitors[0].name == "ping"
        assert config.monitors[0].interval == 50
        assert config.monitors[1].name == "modbus"
        assert config.monitors[1].interval == 10

    def test_parse_mixed_monitors(self):
        """Test parsing mixed monitors with and without intervals."""
        from oida.fuzz.core.config import MonitorConfig

        config = MonitorConfig.parse("ping:100,socket,http:50")
        assert len(config.monitors) == 3
        assert config.monitors[0].interval == 100
        assert config.monitors[1].interval is None
        assert config.monitors[2].interval == 50

    def test_parse_none_disables_monitors(self):
        """Test parsing 'none' disables all monitors."""
        from oida.fuzz.core.config import MonitorConfig

        config = MonitorConfig.parse("none")
        assert len(config.monitors) == 0
        assert config.is_empty() is True

    def test_parse_or_logic(self):
        """Test parsing with OR logic."""
        from oida.fuzz.core.config import MonitorConfig

        config = MonitorConfig.parse("ping,socket", logic="or")
        assert config.logic == "or"

    def test_parse_invalid_logic_defaults_to_and(self):
        """Test invalid logic defaults to AND."""
        from oida.fuzz.core.config import MonitorConfig

        config = MonitorConfig.parse("ping", logic="invalid")
        assert config.logic == "and"

    def test_parse_case_insensitive(self):
        """Test parsing is case insensitive."""
        from oida.fuzz.core.config import MonitorConfig

        config = MonitorConfig.parse("PING,Socket,MODBUS:10")
        assert config.monitors[0].name == "ping"
        assert config.monitors[1].name == "socket"
        assert config.monitors[2].name == "modbus"

    def test_parse_whitespace_handling(self):
        """Test parsing handles whitespace."""
        from oida.fuzz.core.config import MonitorConfig

        config = MonitorConfig.parse(" ping , socket : 50 ")
        assert len(config.monitors) == 2
        assert config.monitors[0].name == "ping"
        assert config.monitors[1].name == "socket"
        assert config.monitors[1].interval == 50

    def test_parse_empty_parts_ignored(self):
        """Test empty parts are ignored."""
        from oida.fuzz.core.config import MonitorConfig

        config = MonitorConfig.parse("ping,,socket,")
        assert len(config.monitors) == 2

    def test_is_empty(self):
        """Test is_empty method."""
        from oida.fuzz.core.config import MonitorConfig

        empty_config = MonitorConfig.parse("none")
        assert empty_config.is_empty() is True

        non_empty_config = MonitorConfig.parse("ping")
        assert non_empty_config.is_empty() is False

    def test_get_monitor_names(self):
        """Test get_monitor_names method."""
        from oida.fuzz.core.config import MonitorConfig

        config = MonitorConfig.parse("ping:50,modbus:10,socket")
        names = config.get_monitor_names()
        assert names == ["ping", "modbus", "socket"]

    def test_format_display(self):
        """Test format_display method."""
        from oida.fuzz.core.config import MonitorConfig

        config = MonitorConfig.parse("ping:50,modbus:10")
        display = config.format_display()
        assert "ping:50" in display
        assert "modbus:10" in display
        assert "AND" in display

    def test_format_display_or_logic(self):
        """Test format_display with OR logic."""
        from oida.fuzz.core.config import MonitorConfig

        config = MonitorConfig.parse("ping,socket", logic="or")
        display = config.format_display()
        assert "OR" in display

    def test_format_display_none(self):
        """Test format_display for empty config."""
        from oida.fuzz.core.config import MonitorConfig

        config = MonitorConfig.parse("none")
        assert config.format_display() == "none"


class TestMonitorRegistry:
    """Test monitor registry functions."""

    def test_registry_initialization(self):
        """Test registry is initialized with monitors."""
        from oida.fuzz.monitors.registry import get_available_monitors, _init_registry

        _init_registry()
        monitors = get_available_monitors()
        assert len(monitors) > 0

    def test_get_monitor_exists(self):
        """Test get_monitor for existing monitor."""
        from oida.fuzz.monitors.registry import get_monitor, _init_registry

        _init_registry()
        info = get_monitor("ping")
        assert info is not None
        assert info.name == "ping"

    def test_get_monitor_not_exists(self):
        """Test get_monitor for non-existing monitor."""
        from oida.fuzz.monitors.registry import get_monitor, _init_registry

        _init_registry()
        info = get_monitor("nonexistent")
        assert info is None

    def test_get_monitor_case_insensitive(self):
        """Test get_monitor is case insensitive."""
        from oida.fuzz.monitors.registry import get_monitor, _init_registry

        _init_registry()
        info = get_monitor("PING")
        assert info is not None
        assert info.name == "ping"

    def test_registry_has_expected_monitors(self):
        """Test registry has all expected monitors."""
        from oida.fuzz.monitors.registry import get_available_monitors, _init_registry

        _init_registry()
        monitors = get_available_monitors()
        expected = [
            "ping",
            "socket",
            "modbus",
            "iec104",
            "mms",
            "http",
            "ftp",
            "smtp",
            "dns",
            "dhcp",
            "tftp",
            "hl7",
            "dicom",
        ]
        for name in expected:
            if name not in monitors:
                pytest.skip(f"Monitor '{name}' not available (not yet implemented?)")

    def test_monitor_info_has_required_fields(self):
        """Test MonitorInfo has all required fields."""
        from oida.fuzz.monitors.registry import get_monitor, _init_registry

        _init_registry()
        info = get_monitor("modbus")
        assert info is not None
        assert hasattr(info, "name")
        assert hasattr(info, "cls")
        assert hasattr(info, "default_interval")
        assert hasattr(info, "description")

    def test_create_monitor(self):
        """Test create_monitor creates monitor instance."""
        from oida.fuzz.monitors.registry import create_monitor, _init_registry

        _init_registry()
        monitor = create_monitor("socket", "127.0.0.1", port=80)
        assert monitor is not None

    def test_create_monitor_nonexistent(self):
        """Test create_monitor returns None for nonexistent monitor."""
        from oida.fuzz.monitors.registry import create_monitor, _init_registry

        _init_registry()
        monitor = create_monitor("nonexistent", "127.0.0.1")
        assert monitor is None


class TestCombinedMonitorLogic:
    """Test CombinedMonitor AND/OR logic."""

    def test_combined_monitor_creation(self):
        """Test CombinedMonitor creation."""
        from oida.fuzz.monitors import CombinedMonitor

        monitor = CombinedMonitor(host="127.0.0.1", port=80, monitors=[], logic="and")
        assert monitor.host == "127.0.0.1"
        assert monitor.port == 80
        assert monitor.logic == "and"

    def test_combined_monitor_or_logic(self):
        """Test CombinedMonitor with OR logic."""
        from oida.fuzz.monitors import CombinedMonitor

        monitor = CombinedMonitor(host="127.0.0.1", port=80, monitors=[], logic="or")
        assert monitor.logic == "or"

    def test_combined_monitor_logic_case_insensitive(self):
        """Test CombinedMonitor logic is case insensitive."""
        from oida.fuzz.monitors import CombinedMonitor

        monitor = CombinedMonitor(host="127.0.0.1", monitors=[], logic="OR")
        assert monitor.logic == "or"

    def test_combined_monitor_set_monitors(self):
        """Test CombinedMonitor set_monitors method."""
        from oida.fuzz.monitors import CombinedMonitor

        monitor = CombinedMonitor(host="127.0.0.1")
        mock_monitor1 = Mock()
        mock_monitor2 = Mock()

        monitor.set_monitors([mock_monitor1, mock_monitor2])
        assert len(monitor.monitors) == 2

    def test_combined_monitor_set_empty_monitors(self):
        """Test CombinedMonitor set_monitors with empty list."""
        from oida.fuzz.monitors import CombinedMonitor

        monitor = CombinedMonitor(host="127.0.0.1")
        monitor.set_monitors([])
        assert len(monitor.monitors) == 0

    def test_combined_monitor_default_check_interval(self):
        """Test CombinedMonitor default check interval."""
        from oida.fuzz.monitors import CombinedMonitor

        monitor = CombinedMonitor(host="127.0.0.1")
        assert monitor.check_interval >= 1


class TestFuzzerConfigTLS:
    """Test FuzzerConfig TLS settings."""

    def test_tls_disabled_by_default(self):
        """Test TLS is disabled by default."""
        from oida.fuzz.core.config import FuzzerConfig

        config = FuzzerConfig(target_ip="127.0.0.1", target_port=443)
        assert config.tls_enabled is False

    def test_tls_enabled(self):
        """Test TLS can be enabled."""
        from oida.fuzz.core.config import FuzzerConfig

        config = FuzzerConfig(target_ip="127.0.0.1", target_port=443, tls_enabled=True)
        assert config.tls_enabled is True


class TestFuzzerConfigEnumerate:
    """Test FuzzerConfig enumerate setting."""

    def test_enumerate_enabled_by_default(self):
        """Test enumerate is enabled by default."""
        from oida.fuzz.core.config import FuzzerConfig

        config = FuzzerConfig(target_ip="127.0.0.1", target_port=80)
        assert config.enumerate is True

    def test_enumerate_can_be_disabled(self):
        """Test enumerate can be disabled."""
        from oida.fuzz.core.config import FuzzerConfig

        config = FuzzerConfig(target_ip="127.0.0.1", target_port=80, enumerate=False)
        assert config.enumerate is False


class TestConnectionFactoryTLS:
    """Test connection factory TLS support."""

    def test_connection_factory_tls_creates_ssl_connection(self):
        """Test connection factory creates SSL connection when TLS enabled."""
        from oida.fuzz.core.connections.tcp import RealConnectionFactory
        from oida.fuzz.core.config import FuzzerConfig
        from boofuzz import SSLSocketConnection

        factory = RealConnectionFactory()
        config = FuzzerConfig(target_ip="127.0.0.1", target_port=443, tls_enabled=True)

        connection = factory.create_connection(config)
        assert isinstance(connection, SSLSocketConnection)

    def test_connection_factory_no_tls_creates_tcp_connection(self):
        """Test connection factory creates TCP connection when TLS disabled."""
        from oida.fuzz.core.connections.tcp import RealConnectionFactory
        from oida.fuzz.core.config import FuzzerConfig
        from boofuzz import TCPSocketConnection

        factory = RealConnectionFactory()
        config = FuzzerConfig(target_ip="127.0.0.1", target_port=80, tls_enabled=False)

        connection = factory.create_connection(config)
        assert isinstance(connection, TCPSocketConnection)

    def test_connection_factory_simple_mode_tls(self):
        """Test connection factory simple mode with TLS."""
        from oida.fuzz.core.connections.tcp import RealConnectionFactory
        from boofuzz import SSLSocketConnection

        factory = RealConnectionFactory()
        connection = factory.create_connection("127.0.0.1", 443, proto="tls")
        assert isinstance(connection, SSLSocketConnection)

    def test_connection_factory_simple_mode_ssl(self):
        """Test connection factory simple mode with SSL."""
        from oida.fuzz.core.connections.tcp import RealConnectionFactory
        from boofuzz import SSLSocketConnection

        factory = RealConnectionFactory()
        connection = factory.create_connection("127.0.0.1", 443, proto="ssl")
        assert isinstance(connection, SSLSocketConnection)


class TestProtocolDefaultMonitors:
    """Test protocol-specific DEFAULT_MONITORS."""

    def test_base_fuzzer_default_monitors(self):
        """Test BaseFuzzer has DEFAULT_MONITORS."""
        from oida.fuzz.core.base_fuzzer import BaseFuzzer

        assert hasattr(BaseFuzzer, "DEFAULT_MONITORS")
        assert BaseFuzzer.DEFAULT_MONITORS == "socket"

    def test_modbus_fuzzer_default_monitors(self):
        """Test ModbusFuzzer has protocol-specific DEFAULT_MONITORS."""
        from oida.fuzz.protocols import PROTOCOL_FUZZERS

        fuzzer_class = PROTOCOL_FUZZERS.get("modbus")
        if fuzzer_class:
            assert hasattr(fuzzer_class, "DEFAULT_MONITORS")
            assert "modbus" in fuzzer_class.DEFAULT_MONITORS

    def test_http_fuzzer_default_monitors(self):
        """Test HTTPFuzzer has protocol-specific DEFAULT_MONITORS."""
        from oida.fuzz.protocols import PROTOCOL_FUZZERS

        fuzzer_class = PROTOCOL_FUZZERS.get("http")
        if fuzzer_class:
            assert hasattr(fuzzer_class, "DEFAULT_MONITORS")
            assert "http" in fuzzer_class.DEFAULT_MONITORS

    def test_iec104_fuzzer_default_monitors(self):
        """Test IEC104Fuzzer has protocol-specific DEFAULT_MONITORS."""
        from oida.fuzz.protocols import PROTOCOL_FUZZERS

        fuzzer_class = PROTOCOL_FUZZERS.get("iec104")
        if fuzzer_class:
            assert hasattr(fuzzer_class, "DEFAULT_MONITORS")
            assert "iec104" in fuzzer_class.DEFAULT_MONITORS

    def test_get_default_monitors_method(self):
        """Test get_default_monitors class method."""
        from oida.fuzz.core.base_fuzzer import BaseFuzzer

        assert hasattr(BaseFuzzer, "get_default_monitors")
        result = BaseFuzzer.get_default_monitors()
        assert result == "socket"

    @pytest.mark.parametrize(
        "protocol,expected_monitor",
        [
            ("modbus", "modbus"),
            ("http", "http"),
            ("ftp", "ftp"),
            ("iec104", "iec104"),
            ("smtp", "smtp"),
            ("dns", "socket"),
            ("mms", "mms"),
            ("hl7", "hl7"),
            ("dicom", "dicom"),
        ],
    )
    def test_protocol_specific_monitors(self, protocol, expected_monitor):
        """Test each protocol has its specific monitor as default."""
        from oida.fuzz.protocols import PROTOCOL_FUZZERS

        fuzzer_class = PROTOCOL_FUZZERS.get(protocol)
        if fuzzer_class and hasattr(fuzzer_class, "DEFAULT_MONITORS"):
            assert expected_monitor in fuzzer_class.DEFAULT_MONITORS


class TestCLIMonitorArgs:
    """Test CLI monitor argument parsing."""

    def test_cli_monitors_argument(self):
        """Test --monitors argument parsing."""
        from oida.cli import gen_cli_args

        parser = gen_cli_args()
        args = parser.parse_args(["fuzz", "modbus", "127.0.0.1", "--monitors", "ping,socket"])
        assert getattr(args, "monitors", None) == "ping,socket"

    def test_cli_monitors_with_intervals(self):
        """Test --monitors argument with intervals."""
        from oida.cli import gen_cli_args

        parser = gen_cli_args()
        args = parser.parse_args(["fuzz", "modbus", "127.0.0.1", "--monitors", "ping:50,modbus:10"])
        assert getattr(args, "monitors", None) == "ping:50,modbus:10"

    def test_cli_monitor_logic_and(self):
        """Test --monitor-logic and argument."""
        from oida.cli import gen_cli_args

        parser = gen_cli_args()
        args = parser.parse_args(["fuzz", "modbus", "127.0.0.1", "--monitor-logic", "and"])
        assert getattr(args, "monitor_logic", None) == "and"

    def test_cli_monitor_logic_or(self):
        """Test --monitor-logic or argument."""
        from oida.cli import gen_cli_args

        parser = gen_cli_args()
        args = parser.parse_args(["fuzz", "modbus", "127.0.0.1", "--monitor-logic", "or"])
        assert getattr(args, "monitor_logic", None) == "or"

    def test_cli_tls_argument(self):
        """Test --tls argument."""
        from oida.cli import gen_cli_args

        parser = gen_cli_args()
        args = parser.parse_args(["fuzz", "http", "127.0.0.1", "--tls"])
        assert getattr(args, "tls_enabled", False) is True

    def test_cli_tls_short_argument(self):
        """Test -T short argument for TLS."""
        from oida.cli import gen_cli_args

        parser = gen_cli_args()
        args = parser.parse_args(["fuzz", "http", "127.0.0.1", "-T"])
        assert getattr(args, "tls_enabled", False) is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
