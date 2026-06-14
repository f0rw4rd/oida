"""
Tests for FuzzerConfig, MonitorConfig, MonitorSpec, ProtocolType, and hexdump.

Tests cover:
- MonitorSpec: dataclass creation, default interval
- MonitorConfig: parse, is_empty, get_monitor_names, format_display
- ProtocolType: enum values
- FuzzerConfig: creation, defaults, get_option, set_option, post_init
- hexdump: formatting binary data
"""


# =============================================================================
# Test MonitorSpec
# =============================================================================


class TestMonitorSpec:
    """Tests for MonitorSpec dataclass."""

    def test_basic_creation(self):
        """MonitorSpec with name only."""
        from src.oida.fuzz.core.config import MonitorSpec

        spec = MonitorSpec(name="ping")
        assert spec.name == "ping"
        assert spec.interval is None

    def test_with_interval(self):
        """MonitorSpec with custom interval."""
        from src.oida.fuzz.core.config import MonitorSpec

        spec = MonitorSpec(name="modbus", interval=10)
        assert spec.name == "modbus"
        assert spec.interval == 10


# =============================================================================
# Test MonitorConfig
# =============================================================================


class TestMonitorConfigParse:
    """Tests for MonitorConfig.parse()."""

    def test_parse_simple(self):
        """Parse simple monitor list."""
        from src.oida.fuzz.core.config import MonitorConfig

        mc = MonitorConfig.parse("ping,socket")
        assert len(mc.monitors) == 2
        assert mc.monitors[0].name == "ping"
        assert mc.monitors[1].name == "socket"
        assert mc.logic == "and"

    def test_parse_with_intervals(self):
        """Parse monitors with intervals."""
        from src.oida.fuzz.core.config import MonitorConfig

        mc = MonitorConfig.parse("ping:50,modbus:10")
        assert mc.monitors[0].name == "ping"
        assert mc.monitors[0].interval == 50
        assert mc.monitors[1].name == "modbus"
        assert mc.monitors[1].interval == 10

    def test_parse_mixed(self):
        """Parse mix of monitors with and without intervals."""
        from src.oida.fuzz.core.config import MonitorConfig

        mc = MonitorConfig.parse("ping:50,socket,modbus:10")
        assert len(mc.monitors) == 3
        assert mc.monitors[0].interval == 50
        assert mc.monitors[1].interval is None
        assert mc.monitors[2].interval == 10

    def test_parse_none_disables(self):
        """Parse 'none' disables all monitors."""
        from src.oida.fuzz.core.config import MonitorConfig

        mc = MonitorConfig.parse("none")
        assert len(mc.monitors) == 0
        assert mc.is_empty() is True

    def test_parse_or_logic(self):
        """Parse with OR logic."""
        from src.oida.fuzz.core.config import MonitorConfig

        mc = MonitorConfig.parse("ping,socket", "or")
        assert mc.logic == "or"

    def test_parse_invalid_logic_defaults_to_and(self):
        """Invalid logic defaults to 'and'."""
        from src.oida.fuzz.core.config import MonitorConfig

        mc = MonitorConfig.parse("ping", "invalid")
        assert mc.logic == "and"

    def test_parse_invalid_interval(self):
        """Invalid interval treated as None."""
        from src.oida.fuzz.core.config import MonitorConfig

        mc = MonitorConfig.parse("ping:abc")
        assert mc.monitors[0].name == "ping"
        assert mc.monitors[0].interval is None

    def test_parse_empty_parts_ignored(self):
        """Empty parts in comma-separated string are ignored."""
        from src.oida.fuzz.core.config import MonitorConfig

        mc = MonitorConfig.parse("ping,,socket,")
        assert len(mc.monitors) == 2

    def test_names_lowercased(self):
        """Monitor names are lowercased."""
        from src.oida.fuzz.core.config import MonitorConfig

        mc = MonitorConfig.parse("Ping,SOCKET")
        assert mc.monitors[0].name == "ping"
        assert mc.monitors[1].name == "socket"


class TestMonitorConfigMethods:
    """Tests for MonitorConfig utility methods."""

    def test_is_empty_true(self):
        """is_empty returns True when no monitors."""
        from src.oida.fuzz.core.config import MonitorConfig

        mc = MonitorConfig.parse("none")
        assert mc.is_empty() is True

    def test_is_empty_false(self):
        """is_empty returns False with monitors."""
        from src.oida.fuzz.core.config import MonitorConfig

        mc = MonitorConfig.parse("ping")
        assert mc.is_empty() is False

    def test_get_monitor_names(self):
        """get_monitor_names returns list of names."""
        from src.oida.fuzz.core.config import MonitorConfig

        mc = MonitorConfig.parse("ping:50,modbus:10,socket")
        names = mc.get_monitor_names()
        assert names == ["ping", "modbus", "socket"]

    def test_format_display_with_monitors(self):
        """format_display with monitors."""
        from src.oida.fuzz.core.config import MonitorConfig

        mc = MonitorConfig.parse("ping:50,socket")
        display = mc.format_display()
        assert "ping:50" in display
        assert "socket" in display
        assert "AND" in display

    def test_format_display_empty(self):
        """format_display with no monitors."""
        from src.oida.fuzz.core.config import MonitorConfig

        mc = MonitorConfig.parse("none")
        assert mc.format_display() == "none"


# =============================================================================
# Test ProtocolType
# =============================================================================


class TestProtocolType:
    """Tests for ProtocolType enum."""

    def test_all_types_exist(self):
        """All expected protocol types defined."""
        from src.oida.fuzz.core.config import ProtocolType

        assert ProtocolType.TCP.value == "tcp"
        assert ProtocolType.SSL.value == "ssl"
        assert ProtocolType.UDP.value == "udp"
        assert ProtocolType.RAW.value == "raw"
        assert ProtocolType.SERIAL.value == "serial"
        assert ProtocolType.IEC104.value == "iec104"
        assert ProtocolType.ICMP.value == "icmp"
        assert ProtocolType.ICMPV6.value == "icmpv6"


# =============================================================================
# Test FuzzerConfig
# =============================================================================


class TestFuzzerConfig:
    """Tests for FuzzerConfig dataclass."""

    def test_minimal_creation(self):
        """FuzzerConfig with minimal args."""
        from src.oida.fuzz.core.config import FuzzerConfig

        config = FuzzerConfig(target_ip="192.168.1.100", target_port=502)
        assert config.target_ip == "192.168.1.100"
        assert config.target_port == 502
        assert config.protocol == "unknown"
        assert config.protocol_options == {}

    def test_defaults(self):
        """FuzzerConfig has expected defaults."""
        from src.oida.fuzz.core.config import FuzzerConfig, ProtocolType

        config = FuzzerConfig(target_ip="10.0.0.1", target_port=80)
        assert config.session_filename == "fuzzer_session"
        assert config.crash_threshold == 5
        assert config.log_session is True
        assert config.skip_pre_send_checks is True
        assert config.monitor_check_interval == 100
        assert config.protocol_type == ProtocolType.TCP
        assert config.web_interface is True
        assert config.console_output is False
        assert config.seed is None
        assert config.tls_enabled is False
        assert config.enumerate is True
        assert config.pause_on_crash is False

    def test_post_init_creates_protocol_options(self):
        """__post_init__ initializes protocol_options if None."""
        from src.oida.fuzz.core.config import FuzzerConfig

        config = FuzzerConfig(target_ip="10.0.0.1", target_port=80)
        assert config.protocol_options is not None
        assert isinstance(config.protocol_options, dict)

    def test_get_option_existing(self):
        """get_option returns existing option value."""
        from src.oida.fuzz.core.config import FuzzerConfig

        config = FuzzerConfig(
            target_ip="10.0.0.1", target_port=80, protocol_options={"timeout": 30}
        )
        assert config.get_option("timeout") == 30

    def test_get_option_missing_returns_default(self):
        """get_option returns default for missing key."""
        from src.oida.fuzz.core.config import FuzzerConfig

        config = FuzzerConfig(target_ip="10.0.0.1", target_port=80)
        assert config.get_option("missing") is None
        assert config.get_option("missing", 42) == 42

    def test_set_option(self):
        """set_option stores a protocol option."""
        from src.oida.fuzz.core.config import FuzzerConfig

        config = FuzzerConfig(target_ip="10.0.0.1", target_port=80)
        config.set_option("timeout", 30)
        assert config.get_option("timeout") == 30

    def test_set_option_creates_dict_if_none(self):
        """set_option creates protocol_options dict if None."""
        from src.oida.fuzz.core.config import FuzzerConfig

        config = FuzzerConfig(target_ip="10.0.0.1", target_port=80)
        config.protocol_options = None
        config.set_option("key", "value")
        assert config.get_option("key") == "value"

    def test_distributed_fuzzing_config(self):
        """Distributed fuzzing config fields."""
        from src.oida.fuzz.core.config import FuzzerConfig

        config = FuzzerConfig(
            target_ip="10.0.0.1", target_port=502, distribution_total=4, distribution_id=2
        )
        assert config.distribution_total == 4
        assert config.distribution_id == 2

    def test_request_filtering_config(self):
        """Request filtering config fields."""
        from src.oida.fuzz.core.config import FuzzerConfig

        config = FuzzerConfig(
            target_ip="10.0.0.1",
            target_port=502,
            enabled_requests=["Auth_Fuzz", "Critical"],
            disabled_requests=["Slow_Test"],
        )
        assert config.enabled_requests == ["Auth_Fuzz", "Critical"]
        assert config.disabled_requests == ["Slow_Test"]


# =============================================================================
# Test hexdump
# =============================================================================


class TestHexdump:
    """Tests for hexdump function."""

    def test_empty_data(self):
        """Hexdump of empty data."""
        from src.oida.fuzz.core.config import hexdump

        result = hexdump(b"")
        assert result == ""

    def test_short_data(self):
        """Hexdump of short data."""
        from src.oida.fuzz.core.config import hexdump

        result = hexdump(b"\x00\x01\x02\x03")
        assert "00000000" in result
        assert "00 01 02 03" in result

    def test_printable_ascii(self):
        """Hexdump shows printable ASCII."""
        from src.oida.fuzz.core.config import hexdump

        result = hexdump(b"Hello")
        assert "Hello" in result

    def test_non_printable_replaced_with_dot(self):
        """Non-printable characters shown as dots."""
        from src.oida.fuzz.core.config import hexdump

        result = hexdump(b"\x00\x01\x02")
        assert "..." in result

    def test_multi_line(self):
        """Data longer than bytes_per_line creates multiple lines."""
        from src.oida.fuzz.core.config import hexdump

        data = bytes(range(32))
        result = hexdump(data, bytes_per_line=16)
        lines = result.strip().split("\n")
        assert len(lines) == 2
        assert "00000000" in lines[0]
        assert "00000010" in lines[1]
