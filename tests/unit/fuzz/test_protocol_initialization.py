"""
Test Protocol Fuzzer Import and Initialization

Tests that all protocol fuzzers in the PROTOCOL_FUZZERS registry
can be imported and initialized with mock connections.
"""

import pytest

from tests.service_gate import require_service
from oida.fuzz.protocols import PROTOCOL_FUZZERS, PROTOCOL_CATEGORIES, PROTOCOL_TO_CATEGORY
from oida.fuzz.core.config import FuzzerConfig
from oida.fuzz.core.connections import MockConnectionFactory


# Protocols that require special system access or optional dependencies
EXPECTED_FAILURES = {
    "raw_socket": ["icmp", "icmpv6", "ipv4", "ipv6", "ethernet", "profinet_dcp"],
    "serial": ["modbus_rtu"],
    "radamsa": [  # Requires pyradamsa optional dependency
        "mutation",
        "http_mutation",
        "modbus_mutation",
        "dnp3_mutation",
        "mqtt_mutation",
    ],
}

ALL_EXPECTED_FAILURES = (
    EXPECTED_FAILURES["raw_socket"] + EXPECTED_FAILURES["serial"] + EXPECTED_FAILURES["radamsa"]
)


@pytest.fixture
def mock_config():
    """Create a mock FuzzerConfig for testing."""
    config = FuzzerConfig(target_ip="127.0.0.1", target_port=9999)
    config.log_session = False
    config.console_output = False
    config.skip_pre_send_checks = True
    return config


@pytest.fixture
def mock_connection_factory():
    """Create a MockConnectionFactory for testing."""
    return MockConnectionFactory()


class TestProtocolImport:
    """Test that all protocols can be imported from the registry."""

    def test_protocol_registry_not_empty(self):
        """Verify protocol registry has entries."""
        assert len(PROTOCOL_FUZZERS.keys()) > 0, "Protocol registry is empty"
        # Some protocols require optional deps (hpack, etc.) so the count
        # may be lower than the full set.  Use a conservative minimum that
        # only accounts for always-available fuzzers.
        assert len(list(PROTOCOL_FUZZERS.keys())) >= 30, (
            f"Expected at least 30 protocols, got {len(list(PROTOCOL_FUZZERS.keys()))}"
        )

    def test_all_protocols_have_category(self):
        """Verify all protocols in registry have a category."""
        uncategorized = []
        for protocol_name in PROTOCOL_FUZZERS.keys():
            if protocol_name not in PROTOCOL_TO_CATEGORY:
                uncategorized.append(protocol_name)

        assert len(uncategorized) == 0, f"Uncategorized protocols: {uncategorized}"

    def test_no_duplicate_protocol_names(self):
        """Verify no duplicate protocol names in registry."""
        names = list(PROTOCOL_FUZZERS.keys())
        assert len(names) == len(set(names)), "Duplicate protocol names found"

    def test_categories_have_protocols(self):
        """Verify all categories have at least one protocol."""
        for category_name, category_data in PROTOCOL_CATEGORIES.items():
            protocols = category_data.get("protocols", [])
            assert len(protocols) > 0, f"Category {category_name} has no protocols"

    def test_category_protocols_exist_in_registry(self):
        """Verify all protocols listed in categories exist in registry."""
        # Protocols that require optional dependencies (may not be installed)
        optional_protocols = {"http2"}  # Requires hpack

        missing = []
        for category_name, category_data in PROTOCOL_CATEGORIES.items():
            for protocol in category_data.get("protocols", []):
                if protocol not in PROTOCOL_FUZZERS and protocol not in optional_protocols:
                    missing.append(f"{category_name}/{protocol}")

        assert len(missing) == 0, f"Protocols in categories but not in registry: {missing}"


class TestProtocolCategories:
    """Test protocol categorization."""

    def test_web_protocols(self):
        """Verify web protocols are present."""
        web_protocols = ["http", "http2"]
        for p in web_protocols:
            if p not in PROTOCOL_FUZZERS:
                require_service(f"Web protocol '{p}' not available (missing optional dep?)")
            assert p in PROTOCOL_FUZZERS, f"Missing web protocol: {p}"

    def test_ics_protocols(self):
        """Verify ICS protocols are present."""
        ics_protocols = ["modbus", "iec104", "dnp3", "bacnet", "ethernetip"]
        for p in ics_protocols:
            assert p in PROTOCOL_FUZZERS, f"Missing ICS protocol: {p}"

    def test_iot_protocols(self):
        """Verify IoT protocols are present."""
        iot_protocols = ["mqtt", "coap"]  # mqtts is an alias, not a separate fuzzer
        for p in iot_protocols:
            assert p in PROTOCOL_FUZZERS, f"Missing IoT protocol: {p}"

    def test_network_protocols(self):
        """Verify network protocols are present."""
        network_protocols = ["dns", "dhcp", "ntp"]  # dns_tcp is handled by dns fuzzer with option
        for p in network_protocols:
            assert p in PROTOCOL_FUZZERS, f"Missing network protocol: {p}"


class TestProtocolInitialization:
    """Test that protocols can be instantiated with mock connections."""

    @pytest.mark.parametrize("protocol_name", ["modbus", "http", "mqtt", "dns", "tcp"])
    def test_implemented_protocol_initialization(
        self, protocol_name, mock_config, mock_connection_factory
    ):
        """Test fuzzer instantiation for implemented protocols."""
        try:
            fuzzer_class = PROTOCOL_FUZZERS[protocol_name]
        except KeyError:
            require_service(f"Protocol {protocol_name} not available")

        try:
            fuzzer = fuzzer_class(config=mock_config, connection_factory=mock_connection_factory)
            assert fuzzer is not None, f"Fuzzer {protocol_name} returned None"
            assert fuzzer.config == mock_config, f"Config not set for {protocol_name}"
            assert fuzzer.connection_factory == mock_connection_factory, (
                f"ConnectionFactory not set for {protocol_name}"
            )
        except ImportError as e:
            if "boofuzz" in str(e):
                require_service("boofuzz not installed")
            raise
        except Exception as e:
            pytest.fail(f"Failed to initialize {protocol_name}: {type(e).__name__}: {e}")

    @pytest.mark.parametrize("protocol_name", list(PROTOCOL_FUZZERS.keys())[:10])
    def test_protocol_has_required_methods(self, protocol_name):
        """Verify each fuzzer has required methods."""
        try:
            fuzzer_class = PROTOCOL_FUZZERS[protocol_name]
        except KeyError:
            require_service(f"Protocol {protocol_name} not loadable")

        assert hasattr(fuzzer_class, "__init__"), f"{protocol_name} missing __init__"
        assert hasattr(fuzzer_class, "_define_protocol"), (
            f"{protocol_name} missing _define_protocol"
        )
        assert hasattr(fuzzer_class, "get_request_definitions"), (
            f"{protocol_name} missing get_request_definitions"
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
