"""
Tests for SNMP Protocol Fuzzers.

Tests cover:
- SNMPv1Fuzzer: SNMPv1 protocol fuzzing
- SNMPv2cFuzzer: SNMPv2c with bulk operations
- SNMP common utilities (OID encoding, IP conversion)
- Request definitions and categories
- ASN.1 BER encoding for SNMP
- Community string attacks
- Amplification patterns
"""

import pytest


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def snmpv1_config():
    """Create a basic SNMPv1 FuzzerConfig."""
    from src.oida.fuzz.core.config import FuzzerConfig, ProtocolType

    config = FuzzerConfig(
        target_ip="192.168.1.100",
        target_port=161,
        protocol_type=ProtocolType.UDP,
    )
    return config


@pytest.fixture
def snmpv2_config():
    """Create a basic SNMPv2c FuzzerConfig."""
    from src.oida.fuzz.core.config import FuzzerConfig, ProtocolType

    config = FuzzerConfig(
        target_ip="192.168.1.100",
        target_port=161,
        protocol_type=ProtocolType.UDP,
    )
    return config


@pytest.fixture
def snmpv1_fuzzer(snmpv1_config):
    """Create an SNMPv1Fuzzer instance with mocked connection."""
    from src.oida.fuzz.protocols.snmpv1 import SNMPv1Fuzzer
    from src.oida.fuzz.core.connections.base import MockConnectionFactory

    factory = MockConnectionFactory()
    fuzzer = SNMPv1Fuzzer(snmpv1_config, connection_factory=factory)
    return fuzzer


@pytest.fixture
def snmpv2_fuzzer(snmpv2_config):
    """Create an SNMPv2cFuzzer instance with mocked connection."""
    from src.oida.fuzz.protocols.snmpv2 import SNMPv2cFuzzer
    from src.oida.fuzz.core.connections.base import MockConnectionFactory

    factory = MockConnectionFactory()
    fuzzer = SNMPv2cFuzzer(snmpv2_config, connection_factory=factory)
    return fuzzer


# =============================================================================
# Test SNMP Common Utilities
# =============================================================================


class TestSNMPCommonEncodeOID:
    """Tests for OID encoding utility."""

    def test_encode_oid_basic(self):
        """Basic OID encoding works."""
        from src.oida.fuzz.protocols.snmp_common import encode_oid

        result = encode_oid("1.3.6.1.2.1")
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_encode_oid_mib2(self):
        """MIB-2 OID prefix encodes correctly."""
        from src.oida.fuzz.protocols.snmp_common import encode_oid

        result = encode_oid("1.3.6.1.2.1.1.1.0")  # sysDescr
        assert isinstance(result, bytes)

    def test_encode_oid_enterprise(self):
        """Enterprise OID encodes correctly."""
        from src.oida.fuzz.protocols.snmp_common import encode_oid

        result = encode_oid("1.3.6.1.4.1.12345.1.2.3")
        assert isinstance(result, bytes)


class TestSNMPCommonIPToBytes:
    """Tests for IP to bytes conversion."""

    def test_ip_to_bytes_valid(self):
        """Valid IP converts to bytes."""
        from src.oida.fuzz.protocols.snmp_common import ip_to_bytes

        result = ip_to_bytes("192.168.1.1")
        assert result == bytes([192, 168, 1, 1])

    def test_ip_to_bytes_zeros(self):
        """Zero IP converts correctly."""
        from src.oida.fuzz.protocols.snmp_common import ip_to_bytes

        result = ip_to_bytes("0.0.0.0")
        assert result == bytes([0, 0, 0, 0])

    def test_ip_to_bytes_max(self):
        """Max IP converts correctly."""
        from src.oida.fuzz.protocols.snmp_common import ip_to_bytes

        result = ip_to_bytes("255.255.255.255")
        assert result == bytes([255, 255, 255, 255])

    def test_ip_to_bytes_invalid_format(self):
        """Invalid IP format raises ValueError."""
        from src.oida.fuzz.protocols.snmp_common import ip_to_bytes

        with pytest.raises(ValueError, match="4 octets"):
            ip_to_bytes("192.168.1")

    def test_ip_to_bytes_invalid_octet(self):
        """Invalid octet value raises ValueError."""
        from src.oida.fuzz.protocols.snmp_common import ip_to_bytes

        with pytest.raises(ValueError, match="out of range"):
            ip_to_bytes("192.168.1.256")


class TestSNMPCommonHexToBytes:
    """Tests for hex to bytes conversion."""

    def test_hex_to_bytes_valid(self):
        """Valid hex string converts to bytes."""
        from src.oida.fuzz.protocols.snmp_common import hex_to_bytes

        result = hex_to_bytes("8000000001020304")
        assert isinstance(result, bytes)
        assert result[0] == 0x80


# =============================================================================
# Test SNMPv1Fuzzer Creation
# =============================================================================


class TestSNMPv1FuzzerCreation:
    """Tests for SNMPv1Fuzzer instantiation."""

    def test_basic_creation(self, snmpv1_config):
        """SNMPv1Fuzzer can be created."""
        from src.oida.fuzz.protocols.snmpv1 import SNMPv1Fuzzer
        from src.oida.fuzz.core.connections.base import MockConnectionFactory

        fuzzer = SNMPv1Fuzzer(snmpv1_config, connection_factory=MockConnectionFactory())
        assert fuzzer is not None

    def test_protocol_type_is_udp(self, snmpv1_config):
        """Protocol type is set to UDP."""
        from src.oida.fuzz.protocols.snmpv1 import SNMPv1Fuzzer
        from src.oida.fuzz.core.connections.base import MockConnectionFactory
        from src.oida.fuzz.core.config import ProtocolType

        fuzzer = SNMPv1Fuzzer(snmpv1_config, connection_factory=MockConnectionFactory())
        assert fuzzer.config.protocol_type == ProtocolType.UDP


class TestSNMPv1FuzzerOptions:
    """Tests for SNMPv1Fuzzer protocol options."""

    def test_protocol_options_defined(self):
        """Protocol options are defined."""
        from src.oida.fuzz.protocols.snmpv1 import SNMPv1Fuzzer

        assert "community" in SNMPv1Fuzzer.PROTOCOL_OPTIONS
        assert "request_id" in SNMPv1Fuzzer.PROTOCOL_OPTIONS
        assert "enable_set" in SNMPv1Fuzzer.PROTOCOL_OPTIONS
        assert "oid_prefix" in SNMPv1Fuzzer.PROTOCOL_OPTIONS

    def test_community_option_default(self):
        """Default community string is 'public'."""
        from src.oida.fuzz.protocols.snmpv1 import SNMPv1Fuzzer

        assert SNMPv1Fuzzer.PROTOCOL_OPTIONS["community"]["default"] == "public"

    def test_trap_options_defined(self):
        """Trap-related options are defined."""
        from src.oida.fuzz.protocols.snmpv1 import SNMPv1Fuzzer

        assert "enterprise_oid" in SNMPv1Fuzzer.PROTOCOL_OPTIONS
        assert "trap_type" in SNMPv1Fuzzer.PROTOCOL_OPTIONS
        assert "specific_trap" in SNMPv1Fuzzer.PROTOCOL_OPTIONS


# =============================================================================
# Test SNMPv1 Request Definitions
# =============================================================================


class TestSNMPv1RequestDefinitions:
    """Tests for SNMPv1 request definitions."""

    def test_get_request_definitions_returns_list(self):
        """get_request_definitions() returns a list."""
        from src.oida.fuzz.protocols.snmpv1 import SNMPv1Fuzzer

        definitions = SNMPv1Fuzzer.get_request_definitions()
        assert isinstance(definitions, list)

    def test_request_definitions_not_empty(self):
        """Request definitions are not empty."""
        from src.oida.fuzz.protocols.snmpv1 import SNMPv1Fuzzer

        definitions = SNMPv1Fuzzer.get_request_definitions()
        assert len(definitions) > 0

    def test_standard_pdu_requests_exist(self):
        """Standard SNMP PDU requests are defined."""
        from src.oida.fuzz.protocols.snmpv1 import SNMPv1Fuzzer

        definitions = SNMPv1Fuzzer.get_request_definitions()
        names = [d.name for d in definitions]

        assert "SNMP_GetRequest" in names
        assert "SNMP_GetNextRequest" in names
        assert "SNMP_SetRequest" in names

    def test_trap_request_exists(self):
        """Trap PDU request is defined."""
        from src.oida.fuzz.protocols.snmpv1 import SNMPv1Fuzzer

        definitions = SNMPv1Fuzzer.get_request_definitions()
        names = [d.name for d in definitions]

        assert "SNMP_Trap" in names

    def test_attack_patterns_exist(self):
        """Attack pattern requests are defined."""
        from src.oida.fuzz.protocols.snmpv1 import SNMPv1Fuzzer

        definitions = SNMPv1Fuzzer.get_request_definitions()
        names = [d.name for d in definitions]

        # Community string attacks
        assert "SNMP_Community_256Bytes" in names
        assert "SNMP_Community_FormatString" in names


# =============================================================================
# Test SNMPv1 PDU Encoding
# =============================================================================


class TestSNMPv1PDUEncoding:
    """Tests for SNMPv1 PDU encoding constants."""

    def test_encode_oid_method(self, snmpv1_fuzzer):
        """_encode_oid() method works."""
        result = snmpv1_fuzzer._encode_oid("1.3.6.1.2.1.1.1.0")
        assert isinstance(result, bytes)

    def test_ip_to_bytes_method(self, snmpv1_fuzzer):
        """_ip_to_bytes() method works."""
        result = snmpv1_fuzzer._ip_to_bytes("192.168.1.100")
        assert isinstance(result, bytes)
        assert len(result) == 4


# =============================================================================
# Test SNMPv2c Fuzzer Creation
# =============================================================================


class TestSNMPv2cFuzzerCreation:
    """Tests for SNMPv2cFuzzer instantiation."""

    def test_basic_creation(self, snmpv2_config):
        """SNMPv2cFuzzer can be created."""
        from src.oida.fuzz.protocols.snmpv2 import SNMPv2cFuzzer
        from src.oida.fuzz.core.connections.base import MockConnectionFactory

        fuzzer = SNMPv2cFuzzer(snmpv2_config, connection_factory=MockConnectionFactory())
        assert fuzzer is not None

    def test_protocol_type_is_udp(self, snmpv2_config):
        """Protocol type is set to UDP."""
        from src.oida.fuzz.protocols.snmpv2 import SNMPv2cFuzzer
        from src.oida.fuzz.core.connections.base import MockConnectionFactory
        from src.oida.fuzz.core.config import ProtocolType

        fuzzer = SNMPv2cFuzzer(snmpv2_config, connection_factory=MockConnectionFactory())
        assert fuzzer.config.protocol_type == ProtocolType.UDP


class TestSNMPv2cFuzzerOptions:
    """Tests for SNMPv2cFuzzer protocol options."""

    def test_protocol_options_defined(self):
        """Protocol options are defined."""
        from src.oida.fuzz.protocols.snmpv2 import SNMPv2cFuzzer

        assert "community" in SNMPv2cFuzzer.PROTOCOL_OPTIONS
        assert "request_id" in SNMPv2cFuzzer.PROTOCOL_OPTIONS
        assert "enable_set" in SNMPv2cFuzzer.PROTOCOL_OPTIONS


# =============================================================================
# Test SNMPv2c Request Definitions
# =============================================================================


class TestSNMPv2cRequestDefinitions:
    """Tests for SNMPv2c request definitions."""

    def test_get_request_definitions_returns_list(self):
        """get_request_definitions() returns a list."""
        from src.oida.fuzz.protocols.snmpv2 import SNMPv2cFuzzer

        definitions = SNMPv2cFuzzer.get_request_definitions()
        assert isinstance(definitions, list)

    def test_bulk_request_exists(self):
        """GetBulkRequest is defined (v2c specific)."""
        from src.oida.fuzz.protocols.snmpv2 import SNMPv2cFuzzer

        definitions = SNMPv2cFuzzer.get_request_definitions()
        names = [d.name for d in definitions]

        assert "SNMPv2c_GetBulkRequest" in names

    def test_inform_request_exists(self):
        """InformRequest is defined (v2c specific)."""
        from src.oida.fuzz.protocols.snmpv2 import SNMPv2cFuzzer

        definitions = SNMPv2cFuzzer.get_request_definitions()
        names = [d.name for d in definitions]

        assert "SNMPv2c_InformRequest" in names

    def test_boundary_tests_exist(self):
        """Boundary tests are defined."""
        from src.oida.fuzz.protocols.snmpv2 import SNMPv2cFuzzer

        definitions = SNMPv2cFuzzer.get_request_definitions()
        names = [d.name for d in definitions]

        assert "SNMPv2c_BoundaryValues" in names


# =============================================================================
# Test Monitor Setup
# =============================================================================


class TestSNMPMonitorSetup:
    """Tests for SNMP monitor setup."""

    def test_snmpv1_monitor_setup(self, snmpv1_fuzzer):
        """SNMPv1 setup_custom_monitors() returns monitors."""
        monitors = snmpv1_fuzzer.setup_custom_monitors()
        assert isinstance(monitors, list)
        assert len(monitors) > 0

    def test_snmpv2_monitor_setup(self, snmpv2_fuzzer):
        """SNMPv2c setup_custom_monitors() returns monitors."""
        monitors = snmpv2_fuzzer.setup_custom_monitors()
        assert isinstance(monitors, list)
        assert len(monitors) > 0

    def test_monitor_uses_correct_port(self, snmpv1_fuzzer):
        """Monitor uses port 161 (SNMP) over UDP (SNMP agents speak UDP,
        so a TCP-connect monitor can never succeed)."""
        from src.oida.fuzz.monitors import SNMPHealthMonitor

        monitors = snmpv1_fuzzer.setup_custom_monitors()
        assert isinstance(monitors[0], SNMPHealthMonitor)
        assert monitors[0].port == 161


# =============================================================================
# Test Security-Relevant Features
# =============================================================================


class TestSNMPSecurityFeatures:
    """Tests for security-relevant SNMP features."""

    def test_community_string_is_fuzzable(self):
        """Community string field should be fuzzable."""
        from src.oida.fuzz.protocols.snmpv1 import SNMPv1Fuzzer

        # The community option exists and can be customized
        assert "community" in SNMPv1Fuzzer.PROTOCOL_OPTIONS
        assert SNMPv1Fuzzer.PROTOCOL_OPTIONS["community"]["type"] == str

    def test_set_requests_disabled_by_default(self):
        """SET requests are disabled by default (safety)."""
        from src.oida.fuzz.protocols.snmpv1 import SNMPv1Fuzzer

        assert SNMPv1Fuzzer.PROTOCOL_OPTIONS["enable_set"]["default"] is False

    def test_request_id_is_fuzzable(self):
        """Request ID can be customized for fuzzing."""
        from src.oida.fuzz.protocols.snmpv1 import SNMPv1Fuzzer

        assert "request_id" in SNMPv1Fuzzer.PROTOCOL_OPTIONS
        assert SNMPv1Fuzzer.PROTOCOL_OPTIONS["request_id"]["type"] == int


# =============================================================================
# Test Amplification Attack Patterns
# =============================================================================


class TestSNMPAmplification:
    """Tests for SNMP amplification attack patterns."""

    def test_getbulk_max_rep_extreme_defined(self):
        """MaxRepExtreme request covers amplification testing."""
        from src.oida.fuzz.protocols.snmpv2 import SNMPv2cFuzzer

        definitions = SNMPv2cFuzzer.get_request_definitions()
        boundary_req = [d for d in definitions if d.name == "SNMPv2c_GetBulk_MaxRepExtreme"]
        assert len(boundary_req) > 0

    def test_snmpv2c_has_boundary_category(self):
        """SNMPv2c has boundary category for amplification tests."""
        from src.oida.fuzz.protocols.snmpv2 import SNMPv2cFuzzer

        definitions = SNMPv2cFuzzer.get_request_definitions()
        categories = {d.category for d in definitions}

        assert "boundary" in categories


# =============================================================================
# Test Error Response Definitions
# =============================================================================


class TestSNMPErrorResponses:
    """Tests for SNMP error response definitions."""

    def test_error_responses_defined(self):
        """Error response PDUs are defined."""
        from src.oida.fuzz.protocols.snmpv1 import SNMPv1Fuzzer

        definitions = SNMPv1Fuzzer.get_request_definitions()
        names = [d.name for d in definitions]

        # Various error codes
        assert "SNMP_GetResponse_NoError" in names
        assert "SNMP_GetResponse_TooBig" in names
        assert "SNMP_GetResponse_NoSuchName" in names


# =============================================================================
# Test Request Categories
# =============================================================================


class TestSNMPRequestCategories:
    """Tests for SNMP request categorization."""

    def test_snmpv1_has_multiple_categories(self):
        """SNMPv1 requests have multiple categories."""
        from src.oida.fuzz.protocols.snmpv1 import SNMPv1Fuzzer

        definitions = SNMPv1Fuzzer.get_request_definitions()
        categories = {d.category for d in definitions}

        # Should have standard, write, response, trap, high_crash
        assert len(categories) >= 3

    def test_high_crash_requests_exist(self):
        """High-crash category requests exist."""
        from src.oida.fuzz.protocols.snmpv1 import SNMPv1Fuzzer

        definitions = SNMPv1Fuzzer.get_request_definitions()
        high_crash = [d for d in definitions if d.category == "high_crash"]

        assert len(high_crash) > 0


# =============================================================================
# Test OID Encoding Correctness
# =============================================================================


class TestOIDEncodingCorrectness:
    """Tests for OID encoding correctness."""

    def test_oid_encoding_starts_with_tag(self):
        """Encoded OID starts with OID tag (0x06)."""
        from src.oida.fuzz.protocols.snmp_common import encode_oid

        result = encode_oid("1.3.6.1.2.1")
        # OID tag is 0x06
        assert result[0] == 0x06

    def test_oid_first_two_components_encoded(self):
        """First two OID components are encoded as (40*first + second)."""
        from src.oida.fuzz.protocols.snmp_common import encode_oid

        # 1.3 encodes as 40*1 + 3 = 43 = 0x2b
        result = encode_oid("1.3")
        # Tag (0x06) + Length (0x01) + Value (0x2b)
        assert 0x2B in result

    def test_oid_length_correct(self):
        """OID length field is correct."""
        from src.oida.fuzz.protocols.snmp_common import encode_oid

        result = encode_oid("1.3.6.1")
        # Tag + Length + Content
        tag = result[0]
        length = result[1]
        content = result[2:]

        assert tag == 0x06
        assert length == len(content)


# =============================================================================
# Test Custom Configuration
# =============================================================================


class TestSNMPCustomConfiguration:
    """Tests for custom SNMP configuration."""

    def test_custom_community_string(self, snmpv1_config):
        """Custom community string is used."""
        from src.oida.fuzz.protocols.snmpv1 import SNMPv1Fuzzer
        from src.oida.fuzz.core.connections.base import MockConnectionFactory

        snmpv1_config.protocol_options = {"community": "private"}
        fuzzer = SNMPv1Fuzzer(snmpv1_config, connection_factory=MockConnectionFactory())
        community = fuzzer.config.get_option("community", "public")
        assert community == "private"

    def test_custom_oid_prefix(self, snmpv1_config):
        """Custom OID prefix is used."""
        from src.oida.fuzz.protocols.snmpv1 import SNMPv1Fuzzer
        from src.oida.fuzz.core.connections.base import MockConnectionFactory

        snmpv1_config.protocol_options = {"oid_prefix": "1.3.6.1.4.1"}
        fuzzer = SNMPv1Fuzzer(snmpv1_config, connection_factory=MockConnectionFactory())
        oid_prefix = fuzzer.config.get_option("oid_prefix", "1.3.6.1.2.1")
        assert oid_prefix == "1.3.6.1.4.1"

    def test_enable_set_option(self, snmpv1_config):
        """Enable SET option can be set."""
        from src.oida.fuzz.protocols.snmpv1 import SNMPv1Fuzzer
        from src.oida.fuzz.core.connections.base import MockConnectionFactory

        snmpv1_config.protocol_options = {"enable_set": True}
        fuzzer = SNMPv1Fuzzer(snmpv1_config, connection_factory=MockConnectionFactory())
        enable_set = fuzzer.config.get_option("enable_set", False)
        assert enable_set is True


# =============================================================================
# Test SNMPv2c Per-Request Gating (regression: coarse-key gates dropped requests)
# =============================================================================


class _RecordingSession:
    """Minimal stand-in for a boofuzz Session that records connected requests."""

    def __init__(self):
        self.connected = []

    def connect(self, request, *args, **kwargs):
        self.connected.append(request.name)


def _connected_request_names(snmpv2_config, *, enabled=None, disabled=None, enable_set=True):
    """Run SNMPv2cFuzzer._define_protocol() with a recording session, no network."""
    from src.oida.fuzz.protocols.snmpv2 import SNMPv2cFuzzer
    from src.oida.fuzz.core.connections.base import MockConnectionFactory

    snmpv2_config.protocol_options = {"enable_set": enable_set}
    if enabled is not None:
        snmpv2_config.enabled_requests = list(enabled)
    if disabled is not None:
        snmpv2_config.disabled_requests = list(disabled)

    fuzzer = SNMPv2cFuzzer(snmpv2_config, connection_factory=MockConnectionFactory())
    # Inject a recording session so _define_protocol() never touches the network.
    recorder = _RecordingSession()
    fuzzer._session = recorder
    fuzzer._define_protocol()
    return recorder.connected


class TestSNMPv2cRequestGating:
    """Every advertised request name must be individually gated and connectable."""

    def test_gate_keys_match_advertised_names(self, snmpv2_config):
        """Default run (no enable/disable, enable_set) connects exactly the advertised names."""
        from src.oida.fuzz.protocols.snmpv2 import SNMPv2cFuzzer

        advertised = {r.name for r in SNMPv2cFuzzer.get_request_definitions()}
        connected = set(_connected_request_names(snmpv2_config, enable_set=True))

        # Every gate key is an advertised name, and every advertised name is gated.
        assert connected == advertised

    def test_set_request_requires_enable_set(self, snmpv2_config):
        """SetRequest only connects when enable_set is True."""
        connected = _connected_request_names(snmpv2_config, enable_set=False)
        assert "SNMPv2c_SetRequest" not in connected
        # All other advertised requests still connect.
        from src.oida.fuzz.protocols.snmpv2 import SNMPv2cFuzzer

        advertised = {r.name for r in SNMPv2cFuzzer.get_request_definitions()}
        assert set(connected) == advertised - {"SNMPv2c_SetRequest"}

    def test_enable_single_request_connects_only_that_request(self, snmpv2_config):
        """--enable SNMPv2c_GetRequest connects only that request (was: zero requests)."""
        connected = _connected_request_names(
            snmpv2_config, enabled=["SNMPv2c_GetRequest"], enable_set=True
        )
        assert connected == ["SNMPv2c_GetRequest"]

    def test_disable_single_request_drops_only_that_request(self, snmpv2_config):
        """--disable SNMPv2c_Malformed drops exactly that request (was: no effect)."""
        connected = _connected_request_names(
            snmpv2_config, disabled=["SNMPv2c_Malformed"], enable_set=True
        )
        from src.oida.fuzz.protocols.snmpv2 import SNMPv2cFuzzer

        advertised = {r.name for r in SNMPv2cFuzzer.get_request_definitions()}
        assert "SNMPv2c_Malformed" not in connected
        assert set(connected) == advertised - {"SNMPv2c_Malformed"}


# =============================================================================
# Test SNMPv3 Per-Request Gating (regression: coarse-key gates dropped requests)
# =============================================================================


def _connected_snmpv3_request_names(*, enabled=None, disabled=None, enable_set=True):
    """Run SNMPv3Fuzzer._define_protocol() with a recording session, no network."""
    from src.oida.fuzz.protocols.snmpv3 import SNMPv3Fuzzer
    from src.oida.fuzz.core.config import FuzzerConfig, ProtocolType
    from src.oida.fuzz.core.connections.base import MockConnectionFactory

    config = FuzzerConfig(
        target_ip="192.168.1.100",
        target_port=161,
        protocol_type=ProtocolType.UDP,
    )
    config.protocol_options = {"enable_set": enable_set}
    if enabled is not None:
        config.enabled_requests = list(enabled)
    if disabled is not None:
        config.disabled_requests = list(disabled)

    fuzzer = SNMPv3Fuzzer(config, connection_factory=MockConnectionFactory())
    # Inject a recording session so _define_protocol() never touches the network.
    recorder = _RecordingSession()
    fuzzer._session = recorder
    fuzzer._define_protocol()
    return recorder.connected


class TestSNMPv3RequestGating:
    """Every advertised request name must be individually gated and connectable."""

    def test_gate_keys_match_advertised_names(self):
        """Default run (no enable/disable, enable_set) connects exactly the advertised names."""
        from src.oida.fuzz.protocols.snmpv3 import SNMPv3Fuzzer

        advertised = {r.name for r in SNMPv3Fuzzer.get_request_definitions()}
        connected = set(_connected_snmpv3_request_names(enable_set=True))

        # Every gate key is an advertised name, and every advertised name is gated.
        assert connected == advertised

    def test_set_request_requires_enable_set(self):
        """SetRequest only connects when enable_set is True."""
        connected = _connected_snmpv3_request_names(enable_set=False)
        assert "SNMPv3_SetRequest" not in connected
        # All other advertised requests still connect.
        from src.oida.fuzz.protocols.snmpv3 import SNMPv3Fuzzer

        advertised = {r.name for r in SNMPv3Fuzzer.get_request_definitions()}
        assert set(connected) == advertised - {"SNMPv3_SetRequest"}

    def test_enable_single_request_connects_only_that_request(self):
        """--enable SNMPv3_USMAuthFuzz connects only that request (was: zero requests)."""
        connected = _connected_snmpv3_request_names(enabled=["SNMPv3_USMAuthFuzz"], enable_set=True)
        assert connected == ["SNMPv3_USMAuthFuzz"]

    def test_disable_single_request_drops_only_that_request(self):
        """--disable SNMPv3_Malformed drops exactly that request (was: no effect)."""
        connected = _connected_snmpv3_request_names(disabled=["SNMPv3_Malformed"], enable_set=True)
        from src.oida.fuzz.protocols.snmpv3 import SNMPv3Fuzzer

        advertised = {r.name for r in SNMPv3Fuzzer.get_request_definitions()}
        assert "SNMPv3_Malformed" not in connected
        assert set(connected) == advertised - {"SNMPv3_Malformed"}


# =============================================================================
# Test SNMPv3 Var-Bind OID Encoding (regression: OID was double-encoded)
# =============================================================================
#
# Bug: every var-bind built its OID as Static("OID_Tag", b"\x06") + Size(...) +
# SmartBytes(self._encode_oid(...)). But _encode_oid() already returns the full
# OBJECT IDENTIFIER TLV (06 <len> <body>), so the wrapper produced
# "06 <len> 06 08 <body>" on the wire -- not a valid OBJECT IDENTIFIER, breaking
# the baseline/standard requests. Fix: emit the SmartBytes TLV directly with no
# outer tag/length wrapper.


def _rendered_snmpv3_requests(enable_set=True):
    """Render every connected SNMPv3 request to bytes, no network."""
    from src.oida.fuzz.protocols.snmpv3 import SNMPv3Fuzzer
    from src.oida.fuzz.core.config import FuzzerConfig, ProtocolType
    from src.oida.fuzz.core.connections.base import MockConnectionFactory

    config = FuzzerConfig(
        target_ip="192.168.1.100",
        target_port=161,
        protocol_type=ProtocolType.UDP,
    )
    config.protocol_options = {"enable_set": enable_set}

    fuzzer = SNMPv3Fuzzer(config, connection_factory=MockConnectionFactory())

    class _Collector:
        def __init__(self):
            self.requests = {}

        def connect(self, request, *args, **kwargs):
            self.requests[request.name] = request

    collector = _Collector()
    fuzzer._session = collector
    fuzzer._define_protocol()
    return {name: req.render() for name, req in collector.requests.items()}


class TestSNMPv3VarBindOIDEncoding:
    """Var-bind OIDs must be a single OBJECT IDENTIFIER, not double-encoded."""

    # OIDs that appear as var-bind names / OID-valued data across the requests.
    OIDS = [
        "1.3.6.1.2.1.1.1.0",
        "1.3.6.1.2.1.1.1",
        "1.3.6.1.2.1.1",
        "1.3.6.1.2.1.1.3.0",
        "1.3.6.1.6.3.1.1.4.1.0",
        "1.3.6.1.4.1.0.1",
        "1.3.6.1.4.1.0.2",
        "1.3.6.1.2.1.1.4.0",
    ]

    def test_no_double_encoded_oid_in_any_request(self):
        """No rendered request contains the double-encoded form 06 <len> 06 ...."""
        from src.oida.fuzz.protocols.snmp_common import encode_oid

        renders = _rendered_snmpv3_requests()
        assert renders, "no SNMPv3 requests were connected"

        for oid in self.OIDS:
            tlv = encode_oid(oid)  # full OBJECT IDENTIFIER TLV (06 <len> <body>)
            double = b"\x06" + bytes([len(tlv)]) + tlv  # the buggy wrapper output
            for name, blob in renders.items():
                assert double not in blob, f"{name}: double-encoded OID {oid} on the wire"

    def test_baseline_requests_carry_single_oid_tlv(self):
        """Baseline requests embed the correct single OBJECT IDENTIFIER TLV."""
        from src.oida.fuzz.protocols.snmp_common import encode_oid

        renders = _rendered_snmpv3_requests()
        sysdescr = encode_oid("1.3.6.1.2.1.1.1.0")

        # Discovery walks sysDescr.0; the exact single TLV must appear verbatim.
        assert "SNMPv3_Discovery" in renders, "SNMPv3_Discovery not connected"
        assert sysdescr in renders["SNMPv3_Discovery"], "Discovery: missing single sysDescr OID TLV"

    def test_rendered_oid_decodes_as_object_identifier(self):
        """The embedded OID bytes decode as a single pyasn1 ObjectIdentifier."""
        from pyasn1.codec.ber import decoder
        from pyasn1.type import univ
        from src.oida.fuzz.protocols.snmp_common import encode_oid

        renders = _rendered_snmpv3_requests()
        sysdescr = encode_oid("1.3.6.1.2.1.1.1.0")
        blob = renders["SNMPv3_Discovery"]

        idx = blob.find(sysdescr)
        assert idx != -1, "sysDescr OID TLV not found in Discovery render"

        decoded, rest = decoder.decode(blob[idx : idx + len(sysdescr)])
        assert isinstance(decoded, univ.ObjectIdentifier)
        assert str(decoded) == "1.3.6.1.2.1.1.1.0"
        assert rest == b""


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
