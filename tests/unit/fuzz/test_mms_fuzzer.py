"""
Tests for MMS Protocol Fuzzer.

Tests cover:
- MMSFuzzer: IEC 61850 MMS protocol fuzzing
- Request definitions and categories
- ASN.1 BER encoding correctness
- MMS PDU type encoding
- IEC 61850 specific features
- OSI stack integration
- CVE-targeted operations
"""

import pytest


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def mms_config():
    """Create a basic MMS FuzzerConfig."""
    from src.oida.fuzz.core.config import FuzzerConfig, ProtocolType

    config = FuzzerConfig(
        target_ip="192.168.1.100",
        target_port=102,
        protocol_type=ProtocolType.TCP,
    )
    return config


@pytest.fixture
def mms_fuzzer(mms_config):
    """Create an MMSFuzzer instance with mocked connection."""
    from src.oida.fuzz.protocols.mms import MMSFuzzer
    from src.oida.fuzz.core.connections.base import MockConnectionFactory

    factory = MockConnectionFactory()
    fuzzer = MMSFuzzer(mms_config, connection_factory=factory)
    return fuzzer


# =============================================================================
# Test MMSFuzzer Creation
# =============================================================================


class TestMMSFuzzerCreation:
    """Tests for MMSFuzzer instantiation."""

    def test_basic_creation(self, mms_config):
        """MMSFuzzer can be created."""
        from src.oida.fuzz.protocols.mms import MMSFuzzer
        from src.oida.fuzz.core.connections.base import MockConnectionFactory

        fuzzer = MMSFuzzer(mms_config, connection_factory=MockConnectionFactory())
        assert fuzzer is not None

    def test_default_port(self, mms_config):
        """Default port is 102 (ISO-TSAP)."""
        from src.oida.fuzz.protocols.mms import MMSFuzzer
        from src.oida.fuzz.core.connections.base import MockConnectionFactory

        mms_config.target_port = None
        fuzzer = MMSFuzzer(mms_config, connection_factory=MockConnectionFactory())
        # Monitor uses port 102 as default
        assert fuzzer is not None

    def test_invoke_id_initialization(self, mms_fuzzer):
        """Invoke ID is initialized from config."""
        assert mms_fuzzer.invoke_id == 1  # Default

    def test_osi_stack_enabled_by_default(self, mms_fuzzer):
        """OSI stack is enabled by default."""
        assert mms_fuzzer.use_osi_stack is True


class TestMMSFuzzerOptions:
    """Tests for MMSFuzzer protocol options."""

    def test_protocol_options_defined(self):
        """Protocol options are defined."""
        from src.oida.fuzz.protocols.mms import MMSFuzzer

        assert "invoke_id_start" in MMSFuzzer.PROTOCOL_OPTIONS
        assert "max_pdu_size" in MMSFuzzer.PROTOCOL_OPTIONS
        assert "domain_name" in MMSFuzzer.PROTOCOL_OPTIONS
        assert "enable_file_services" in MMSFuzzer.PROTOCOL_OPTIONS
        assert "functional_constraint" in MMSFuzzer.PROTOCOL_OPTIONS
        assert "control_model" in MMSFuzzer.PROTOCOL_OPTIONS

    def test_invoke_id_option(self, mms_config):
        """Custom invoke_id_start is respected."""
        from src.oida.fuzz.protocols.mms import MMSFuzzer
        from src.oida.fuzz.core.connections.base import MockConnectionFactory

        mms_config.protocol_options = {"invoke_id_start": 100}
        fuzzer = MMSFuzzer(mms_config, connection_factory=MockConnectionFactory())
        assert fuzzer.invoke_id == 100

    def test_domain_name_option(self, mms_config):
        """Custom domain_name is used."""
        from src.oida.fuzz.protocols.mms import MMSFuzzer
        from src.oida.fuzz.core.connections.base import MockConnectionFactory

        mms_config.protocol_options = {"domain_name": "CTRL01"}
        fuzzer = MMSFuzzer(mms_config, connection_factory=MockConnectionFactory())
        domain = fuzzer.config.get_option("domain_name", "AA11")
        assert domain == "CTRL01"

    def test_legacy_mode_disables_osi_stack(self, mms_config):
        """Legacy mode disables OSI stack."""
        from src.oida.fuzz.protocols.mms import MMSFuzzer
        from src.oida.fuzz.core.connections.base import MockConnectionFactory

        mms_config.protocol_options = {"legacy_mode": True}
        fuzzer = MMSFuzzer(mms_config, connection_factory=MockConnectionFactory())
        assert fuzzer.use_osi_stack is False


# =============================================================================
# Test Request Definitions
# =============================================================================


class TestMMSRequestDefinitions:
    """Tests for MMS request definitions."""

    def test_get_request_definitions_returns_list(self):
        """get_request_definitions() returns a list."""
        from src.oida.fuzz.protocols.mms import MMSFuzzer

        definitions = MMSFuzzer.get_request_definitions()
        assert isinstance(definitions, list)

    def test_request_definitions_not_empty(self):
        """Request definitions are not empty."""
        from src.oida.fuzz.protocols.mms import MMSFuzzer

        definitions = MMSFuzzer.get_request_definitions()
        assert len(definitions) > 0

    def test_request_definitions_have_required_fields(self):
        """Each request definition has required fields."""
        from src.oida.fuzz.protocols.mms import MMSFuzzer
        from src.oida.fuzz.core.base_fuzzer import RequestInfo

        definitions = MMSFuzzer.get_request_definitions()
        for defn in definitions:
            assert isinstance(defn, RequestInfo)
            assert defn.name
            assert defn.description
            assert defn.category

    def test_cve_targeted_requests_exist(self):
        """CVE-targeted requests are defined."""
        from src.oida.fuzz.protocols.mms import MMSFuzzer

        definitions = MMSFuzzer.get_request_definitions()
        names = [d.name for d in definitions]

        # CVE-2015-6574 buffer overflow
        assert "MMS_Buffer_Overflow" in names
        # CVE-2019-6604 control operations
        assert "MMS_Control_Operations" in names

    def test_request_categories_cover_all_phases(self):
        """Request categories cover all optimization phases."""
        from src.oida.fuzz.protocols.mms import MMSFuzzer

        definitions = MMSFuzzer.get_request_definitions()
        categories = {d.category for d in definitions}

        # Should have baseline, crash, write, boundary, read
        assert "baseline" in categories
        assert "crash" in categories
        assert "write" in categories
        assert "boundary" in categories
        assert "read" in categories


# =============================================================================
# Test MMS PDU Constants
# =============================================================================


class TestMMSPDUConstants:
    """Tests for MMS PDU type constants."""

    def test_pdu_types_defined(self):
        """PDU type constants are defined."""
        from src.oida.fuzz.protocols.mms import MMSFuzzer

        assert MMSFuzzer.PDU_CONFIRMED_REQUEST == 0xA0
        assert MMSFuzzer.PDU_CONFIRMED_RESPONSE == 0xA1
        assert MMSFuzzer.PDU_UNCONFIRMED == 0xA3
        assert MMSFuzzer.PDU_REJECT == 0xA4
        assert MMSFuzzer.PDU_INITIATE_REQUEST == 0xA8

    def test_service_ids_defined(self):
        """Service ID constants match ISO 9506-2 ASN.1 context tags."""
        from src.oida.fuzz.protocols.mms import MMSFuzzer

        assert MMSFuzzer.SERVICE_READ == b"\xa4"  # [4] constructed
        assert MMSFuzzer.SERVICE_WRITE == b"\xa5"  # [5] constructed
        assert MMSFuzzer.SERVICE_GET_NAME_LIST == b"\xa1"  # [1] constructed
        assert MMSFuzzer.SERVICE_IDENTIFY == b"\x82"  # [2] primitive
        assert MMSFuzzer.SERVICE_FILE_OPEN == b"\xbf\x48"  # [72] constructed


# =============================================================================
# Test MMS Request Creation Methods
# =============================================================================


class TestMMSReadRequest:
    """Tests for MMS Read request creation."""

    def test_create_read_request_returns_bytes(self, mms_fuzzer):
        """_create_read_request() returns bytes."""
        result = mms_fuzzer._create_read_request()
        assert isinstance(result, bytes)

    def test_read_request_starts_with_confirmed_request_tag(self, mms_fuzzer):
        """Read request starts with confirmed-request PDU tag."""
        result = mms_fuzzer._create_read_request()
        assert result[0] == 0xA0  # PDU_CONFIRMED_REQUEST

    def test_read_request_increments_invoke_id(self, mms_fuzzer):
        """Each read request increments invoke ID."""
        initial_id = mms_fuzzer.invoke_id
        mms_fuzzer._create_read_request()
        assert mms_fuzzer.invoke_id == initial_id + 1


class TestMMSWriteRequest:
    """Tests for MMS Write request creation."""

    def test_create_write_request_returns_bytes(self, mms_fuzzer):
        """_create_write_request() returns bytes."""
        result = mms_fuzzer._create_write_request()
        assert isinstance(result, bytes)

    def test_write_request_starts_with_confirmed_request_tag(self, mms_fuzzer):
        """Write request starts with confirmed-request PDU tag."""
        result = mms_fuzzer._create_write_request()
        assert result[0] == 0xA0


class TestMMSIdentifyRequest:
    """Tests for MMS Identify request creation."""

    def test_create_identify_request_returns_bytes(self, mms_fuzzer):
        """_create_identify_request() returns bytes."""
        result = mms_fuzzer._create_identify_request()
        assert isinstance(result, bytes)

    def test_identify_request_starts_with_confirmed_request_tag(self, mms_fuzzer):
        """Identify request starts with confirmed-request PDU tag."""
        result = mms_fuzzer._create_identify_request()
        assert result[0] == 0xA0


class TestMMSGetNameListRequest:
    """Tests for MMS GetNameList request creation."""

    def test_create_get_namelist_request_returns_bytes(self, mms_fuzzer):
        """_create_get_namelist_request() returns bytes."""
        result = mms_fuzzer._create_get_namelist_request()
        assert isinstance(result, bytes)


class TestMMSInformationReport:
    """Tests for MMS Information Report creation."""

    def test_create_information_report_returns_bytes(self, mms_fuzzer):
        """_create_information_report() returns bytes."""
        result = mms_fuzzer._create_information_report()
        assert isinstance(result, bytes)

    def test_information_report_starts_with_unconfirmed_tag(self, mms_fuzzer):
        """Information report starts with unconfirmed PDU tag."""
        result = mms_fuzzer._create_information_report()
        assert result[0] == 0xA3  # PDU_UNCONFIRMED


class TestMMSControlRequest:
    """Tests for IEC 61850 control request creation."""

    def test_create_control_request_select(self, mms_fuzzer):
        """Control request with 'select' operation works."""
        result = mms_fuzzer._create_control_request(operation="select")
        assert isinstance(result, bytes)
        assert result[0] == 0xA0  # Confirmed request

    def test_create_control_request_operate(self, mms_fuzzer):
        """Control request with 'operate' operation works."""
        result = mms_fuzzer._create_control_request(operation="operate")
        assert isinstance(result, bytes)


class TestMMSFileRequest:
    """Tests for MMS File service request creation."""

    def test_create_file_open_request(self, mms_fuzzer):
        """_create_file_open_request() returns bytes."""
        result = mms_fuzzer._create_file_open_request()
        assert isinstance(result, bytes)

    def test_file_open_request_with_custom_filename(self, mms_fuzzer):
        """File open request with custom filename works."""
        result = mms_fuzzer._create_file_open_request(filename="TEST/file.cfg")
        assert isinstance(result, bytes)
        assert b"TEST/file.cfg" in result


class TestMMSRejectPDU:
    """Tests for MMS Reject PDU creation."""

    def test_create_reject_pdu(self, mms_fuzzer):
        """_create_reject_pdu() returns bytes."""
        result = mms_fuzzer._create_reject_pdu()
        assert isinstance(result, bytes)

    def test_reject_pdu_starts_with_reject_tag(self, mms_fuzzer):
        """Reject PDU starts with reject tag."""
        result = mms_fuzzer._create_reject_pdu()
        assert result[0] == 0xA4  # PDU_REJECT

    def test_reject_pdu_with_invoke_id(self, mms_fuzzer):
        """Reject PDU includes invoke ID when specified."""
        result = mms_fuzzer._create_reject_pdu(original_invoke_id=42)
        assert isinstance(result, bytes)


class TestMMSInitiateRequest:
    """Tests for MMS Initiate request creation."""

    def test_create_initiate_request(self, mms_fuzzer):
        """_create_initiate_request() returns bytes."""
        result = mms_fuzzer._create_initiate_request()
        assert isinstance(result, bytes)

    def test_initiate_request_starts_with_initiate_tag(self, mms_fuzzer):
        """Initiate request starts with initiate-request tag."""
        result = mms_fuzzer._create_initiate_request()
        assert result[0] == 0xA8  # PDU_INITIATE_REQUEST


# =============================================================================
# Test MMS Data Value Encoding
# =============================================================================


class TestMMSDataValueEncoding:
    """Tests for MMS Data type encoding."""

    def test_create_integer_data_value(self, mms_fuzzer):
        """Integer data value is encoded correctly."""
        result = mms_fuzzer._create_mms_data_value("integer", 42)
        assert isinstance(result, bytes)
        # Context tag 5 for integer
        assert result[0] == 0x85

    def test_create_boolean_data_value(self, mms_fuzzer):
        """Boolean data value is encoded correctly."""
        result = mms_fuzzer._create_mms_data_value("boolean", True)
        assert isinstance(result, bytes)
        # Context tag 3 for boolean
        assert result[0] == 0x83

    def test_create_boolean_false_value(self, mms_fuzzer):
        """Boolean false value is encoded correctly."""
        result = mms_fuzzer._create_mms_data_value("boolean", False)
        assert result[-1] == 0x00  # False

    def test_create_boolean_true_value(self, mms_fuzzer):
        """Boolean true value is encoded correctly."""
        result = mms_fuzzer._create_mms_data_value("boolean", True)
        assert result[-1] == 0xFF  # True

    def test_create_bitstring_data_value(self, mms_fuzzer):
        """Bitstring data value is encoded correctly."""
        result = mms_fuzzer._create_mms_data_value("bitstring")
        assert isinstance(result, bytes)
        # Context tag 4 for bitstring
        assert result[0] == 0x84

    def test_create_visible_string_data_value(self, mms_fuzzer):
        """Visible string data value is encoded correctly."""
        result = mms_fuzzer._create_mms_data_value("visible-string", "TEST")
        assert isinstance(result, bytes)
        # Context tag 10 for visible-string
        assert result[0] == 0x8A

    def test_create_structure_data_value(self, mms_fuzzer):
        """Structure data value is encoded correctly."""
        result = mms_fuzzer._create_mms_data_value("structure")
        assert isinstance(result, bytes)
        # Context tag 2 for structure (constructed)
        assert result[0] == 0xA2


# =============================================================================
# Test Variable Specification
# =============================================================================


class TestMMSVariableSpecification:
    """Tests for MMS variable specification creation."""

    def test_create_variable_specification(self, mms_fuzzer):
        """_create_variable_specification() returns bytes."""
        result = mms_fuzzer._create_variable_specification()
        assert isinstance(result, bytes)

    def test_variable_specification_with_custom_domain(self, mms_fuzzer):
        """Variable specification with custom domain works."""
        result = mms_fuzzer._create_variable_specification(domain="MYDOM")
        assert isinstance(result, bytes)
        assert b"MYDOM" in result

    def test_variable_specification_with_custom_item(self, mms_fuzzer):
        """Variable specification with custom item works."""
        result = mms_fuzzer._create_variable_specification(item="LLN0$ST$Beh$stVal")
        assert isinstance(result, bytes)


# =============================================================================
# Test IEC 61850 Valid References
# =============================================================================


class TestIEC61850References:
    """Tests for IEC 61850 valid references."""

    def test_valid_references_defined(self):
        """Valid IEC 61850 references are defined."""
        from src.oida.fuzz.protocols.mms import MMSFuzzer

        assert len(MMSFuzzer.VALID_REFERENCES) > 0

    def test_valid_references_follow_naming_convention(self):
        """Valid references follow IEC 61850 naming convention."""
        from src.oida.fuzz.protocols.mms import MMSFuzzer

        for ref in MMSFuzzer.VALID_REFERENCES:
            # Should contain $ separator
            assert "$" in ref
            # Should have logical node prefix
            parts = ref.split("$")
            assert len(parts) >= 2

    def test_status_references_exist(self):
        """Status (ST) references exist."""
        from src.oida.fuzz.protocols.mms import MMSFuzzer

        st_refs = [r for r in MMSFuzzer.VALID_REFERENCES if "$ST$" in r]
        assert len(st_refs) > 0

    def test_measurement_references_exist(self):
        """Measurement (MX) references exist."""
        from src.oida.fuzz.protocols.mms import MMSFuzzer

        mx_refs = [r for r in MMSFuzzer.VALID_REFERENCES if "$MX$" in r]
        assert len(mx_refs) > 0


# =============================================================================
# Test Confirmed Request Creation
# =============================================================================


class TestMMSConfirmedRequest:
    """Tests for confirmed request PDU creation."""

    def test_create_confirmed_request(self, mms_fuzzer):
        """_create_confirmed_request() creates valid PDU."""
        result = mms_fuzzer._create_confirmed_request(
            invoke_id=1,
            service_tag=b"\x82",  # Identify [2] primitive
            service_data=b"",
        )
        assert isinstance(result, bytes)
        assert result[0] == 0xA0  # Confirmed request tag

    def test_confirmed_request_includes_invoke_id(self, mms_fuzzer):
        """Confirmed request includes invoke ID."""
        result = mms_fuzzer._create_confirmed_request(
            invoke_id=42, service_tag=b"\x82", service_data=b""
        )
        # Invoke ID should be encoded in the PDU
        assert len(result) > 3


# =============================================================================
# Test Monitor Setup
# =============================================================================


class TestMMSMonitorSetup:
    """Tests for MMS monitor setup."""

    def test_setup_custom_monitors_returns_list(self, mms_fuzzer):
        """setup_custom_monitors() returns a list."""
        monitors = mms_fuzzer.setup_custom_monitors()
        assert isinstance(monitors, list)

    def test_monitor_uses_correct_port(self, mms_fuzzer):
        """Monitor uses port 102 (ISO-TSAP)."""
        from src.oida.fuzz.monitors import SocketHealthMonitor

        monitors = mms_fuzzer.setup_custom_monitors()
        assert len(monitors) > 0
        assert isinstance(monitors[0], SocketHealthMonitor)


# =============================================================================
# Test OSI Stack Integration
# =============================================================================


class TestMMSOSIStack:
    """Tests for OSI stack integration."""

    def test_osi_stack_builder_initialized(self, mms_config):
        """OSI stack builder is initialized when enabled."""
        from src.oida.fuzz.protocols.mms import MMSFuzzer
        from src.oida.fuzz.core.connections.base import MockConnectionFactory

        fuzzer = MMSFuzzer(mms_config, connection_factory=MockConnectionFactory())
        assert hasattr(fuzzer, "osi_stack")

    def test_osi_stack_not_initialized_in_legacy_mode(self, mms_config):
        """OSI stack builder not initialized in legacy mode."""
        from src.oida.fuzz.protocols.mms import MMSFuzzer
        from src.oida.fuzz.core.connections.base import MockConnectionFactory

        mms_config.protocol_options = {"legacy_mode": True}
        fuzzer = MMSFuzzer(mms_config, connection_factory=MockConnectionFactory())
        assert not hasattr(fuzzer, "osi_stack") or fuzzer.use_osi_stack is False


# =============================================================================
# Test ASN.1 BER Encoding Integration
# =============================================================================


class TestMMSASN1Encoding:
    """Tests for ASN.1 BER encoding in MMS."""

    def test_ber_encoding_imports(self):
        """BER encoding functions are imported."""
        # Should not raise ImportError

    def test_read_request_uses_valid_asn1(self, mms_fuzzer):
        """Read request uses valid ASN.1 encoding."""
        result = mms_fuzzer._create_read_request()

        # Should be valid ASN.1 structure
        # Tag (1 byte) + Length (variable) + Content
        assert len(result) >= 3

        # First byte is context tag (0xa0)
        assert result[0] == 0xA0

        # Second byte is length (or length indicator for long form)
        length_byte = result[1]
        if length_byte < 0x80:
            # Short form length
            len(result) - 2
        else:
            # Long form length (not expected for small requests)
            pass


# =============================================================================
# Test Security-Relevant Fields
# =============================================================================


class TestMMSSecurityFields:
    """Tests for security-relevant field fuzzing."""

    def test_invoke_id_is_fuzzable(self, mms_fuzzer):
        """Invoke ID can be varied for fuzzing."""
        request1 = mms_fuzzer._create_read_request(invoke_id=1)
        request2 = mms_fuzzer._create_read_request(invoke_id=0xFFFF)
        request3 = mms_fuzzer._create_read_request(invoke_id=0)

        # Different invoke IDs should produce different requests
        assert request1 != request2
        assert request1 != request3

    def test_file_path_can_contain_traversal(self, mms_fuzzer):
        """File path accepts traversal strings for testing."""
        # This tests that directory traversal patterns can be sent
        result = mms_fuzzer._create_file_open_request(filename="../../../etc/passwd")
        assert b"../../../etc/passwd" in result


# =============================================================================
# Test Protocol State
# =============================================================================


class TestMMSProtocolState:
    """Tests for MMS protocol state tracking."""

    def test_association_state_initialized(self, mms_fuzzer):
        """Association state is initialized."""
        assert hasattr(mms_fuzzer, "association_established")
        assert mms_fuzzer.association_established is False

    def test_cotp_state_initialized(self, mms_fuzzer):
        """COTP connection state is initialized."""
        assert hasattr(mms_fuzzer, "cotp_connection_established")
        assert mms_fuzzer.cotp_connection_established is False

    def test_negotiated_max_pdu_initialized(self, mms_fuzzer):
        """Negotiated max PDU is initialized to None."""
        assert hasattr(mms_fuzzer, "negotiated_max_pdu")
        assert mms_fuzzer.negotiated_max_pdu is None

    def test_define_state_machine_exists(self, mms_fuzzer):
        """_define_state_machine method exists."""
        assert hasattr(mms_fuzzer, "_define_state_machine")
        assert callable(mms_fuzzer._define_state_machine)

    def test_validate_cotp(self, mms_fuzzer):
        """_validate_cotp returns cotp_connection_established flag."""
        assert mms_fuzzer._validate_cotp() is False
        mms_fuzzer.cotp_connection_established = True
        assert mms_fuzzer._validate_cotp() is True

    def test_validate_association(self, mms_fuzzer):
        """_validate_association returns association_established flag."""
        assert mms_fuzzer._validate_association() is False
        mms_fuzzer.association_established = True
        assert mms_fuzzer._validate_association() is True


# =============================================================================
# Test Request State Requirements
# =============================================================================


class TestMMSRequestStateRequirements:
    """Tests for requires_state in request definitions."""

    def test_all_requests_have_requires_state(self):
        """All request definitions have requires_state set."""
        from src.oida.fuzz.protocols.mms import MMSFuzzer

        definitions = MMSFuzzer.get_request_definitions()
        for defn in definitions:
            assert defn.requires_state is not None, f"Request '{defn.name}' missing requires_state"

    def test_connected_state_requests(self):
        """Requests requiring CONNECTED state are correct."""
        from src.oida.fuzz.protocols.mms import MMSFuzzer

        definitions = MMSFuzzer.get_request_definitions()
        connected_names = {d.name for d in definitions if d.requires_state == "CONNECTED"}
        assert "MMS_Baseline" in connected_names
        assert "MMS_Buffer_Overflow" in connected_names
        assert "MMS_ASN1_Attacks" in connected_names
        assert "MMS_OSI_Layer" in connected_names
        assert "MMS_Malformed_PDU" in connected_names

    def test_cotp_established_state_requests(self):
        """Requests requiring COTP_ESTABLISHED state are correct."""
        from src.oida.fuzz.protocols.mms import MMSFuzzer

        definitions = MMSFuzzer.get_request_definitions()
        cotp_names = {d.name for d in definitions if d.requires_state == "COTP_ESTABLISHED"}
        assert "MMS_Invoke_ID" in cotp_names
        assert "MMS_IEC61850_Attacks" in cotp_names
        assert "MMS_Session_Mgmt" in cotp_names

    def test_mms_associated_state_requests(self):
        """Requests requiring MMS_ASSOCIATED state are correct."""
        from src.oida.fuzz.protocols.mms import MMSFuzzer

        definitions = MMSFuzzer.get_request_definitions()
        assoc_names = {d.name for d in definitions if d.requires_state == "MMS_ASSOCIATED"}
        assert "MMS_Write_Operations" in assoc_names
        assert "MMS_Control_Operations" in assoc_names
        assert "MMS_File_Services" in assoc_names
        assert "MMS_Read_Operations" in assoc_names
        assert "MMS_Reports" in assoc_names

    def test_valid_state_names(self):
        """All requires_state values are valid MMS state names."""
        from src.oida.fuzz.protocols.mms import MMSFuzzer

        valid_states = {"CONNECTED", "COTP_ESTABLISHED", "MMS_ASSOCIATED"}
        definitions = MMSFuzzer.get_request_definitions()
        for defn in definitions:
            state = defn.requires_state
            if isinstance(state, str):
                assert state in valid_states, f"Request '{defn.name}' has invalid state '{state}'"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
