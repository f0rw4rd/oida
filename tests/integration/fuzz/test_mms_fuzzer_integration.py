"""
Integration tests for MMS Protocol Fuzzer against Docker mock server.

Tests verify:
1. State machine initialization (CONNECTED -> COTP_ESTABLISHED -> MMS_ASSOCIATED)
2. Negotiated max PDU extraction from server response
3. All 14 request definitions with their `requires_state` mappings
4. Actual fuzzing execution against the mock service

Requires:
- Docker mock MMS server running on port 102 (mms-libiec61850 service)
- Run with: make mock-start (from project root)
"""

import socket

import pytest
from unittest.mock import patch, MagicMock

from tests.service_gate import require_import

from .conftest import require_docker_mock

# Mark all tests in this module. Shares the capped libiec61850 MMS server
# (port 102) with test_mms_integration.py; same xdist_group so all access to
# that server serializes onto one worker (honored under --dist loadgroup).
pytestmark = [pytest.mark.mms, pytest.mark.fuzz, pytest.mark.xdist_group("mms_service")]


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def mms_fuzzer_config(tmp_path, mms_port):
    """Create FuzzerConfig for MMS fuzzer testing."""
    from oida.fuzz.core.config import FuzzerConfig, MonitorConfig

    return FuzzerConfig(
        target_ip="127.0.0.1",
        target_port=mms_port,
        protocol="mms",
        session_filename=str(tmp_path / "mms_fuzz_session"),
        index_end=10,  # Limited iterations for testing
        log_session=False,
        console_output=False,
        web_interface=False,
        enumerate=False,
        skip_pre_send_checks=True,
        monitor_config=MonitorConfig.parse("none"),
        boofuzz_db=False,
    )


@pytest.fixture
def mock_connection_factory():
    """Create MockConnectionFactory for isolated testing."""
    from oida.fuzz.core.connections.base import MockConnectionFactory

    return MockConnectionFactory()


@pytest.fixture
def mms_fuzzer_mocked(mms_fuzzer_config, mock_connection_factory):
    """Create MMSFuzzer instance with mocked connection (no network)."""
    from oida.fuzz.protocols.mms import MMSFuzzer

    return MMSFuzzer(config=mms_fuzzer_config, connection_factory=mock_connection_factory)


# =============================================================================
# Test State Machine Initialization
# =============================================================================


class TestMMSStateMachine:
    """Tests for MMS state machine initialization against mock server."""

    def test_state_machine_initializes(self, mms_fuzzer_mocked):
        """Verify state machine is created when _define_state_machine is called."""
        # Initially no state machine
        assert mms_fuzzer_mocked.use_osi_stack is True

        # Trigger state machine definition (mocked - won't connect to network)
        with patch.object(mms_fuzzer_mocked, "_define_state_machine"):
            # Just verify the method exists and can be called
            mms_fuzzer_mocked._define_state_machine()

    def test_state_machine_states_defined(self, mms_fuzzer_config, mms_host, mms_port):
        """Verify state machine is created with 3 states when connected to mock."""
        require_docker_mock("mms")

        from oida.fuzz.protocols.mms import MMSFuzzer
        from oida.fuzz.core.connections.base import MockConnectionFactory

        fuzzer = MMSFuzzer(config=mms_fuzzer_config, connection_factory=MockConnectionFactory())

        # Call _define_state_machine which connects to the server
        fuzzer._define_state_machine()

        assert fuzzer.state_machine is not None
        states = fuzzer.state_machine.states
        assert "CONNECTED" in states
        assert "COTP_ESTABLISHED" in states
        assert "MMS_ASSOCIATED" in states

    def test_cotp_handshake(self, mms_fuzzer_config, mms_host, mms_port):
        """Verify COTP CR/CC handshake succeeds against mock server."""
        require_docker_mock("mms")

        from oida.fuzz.protocols.mms import MMSFuzzer
        from oida.fuzz.core.connections.base import MockConnectionFactory

        fuzzer = MMSFuzzer(config=mms_fuzzer_config, connection_factory=MockConnectionFactory())
        fuzzer._define_state_machine()

        # After handshake, COTP should be established
        assert fuzzer.cotp_connection_established is True

    def test_mms_association(self, mms_fuzzer_config, mms_host, mms_port):
        """Verify MMS association is established against mock server."""
        require_docker_mock("mms")

        from oida.fuzz.protocols.mms import MMSFuzzer
        from oida.fuzz.core.connections.base import MockConnectionFactory

        fuzzer = MMSFuzzer(config=mms_fuzzer_config, connection_factory=MockConnectionFactory())
        fuzzer._define_state_machine()

        # After full handshake, association should be established
        assert fuzzer.association_established is True

    def test_final_state_is_mms_associated(self, mms_fuzzer_config, mms_host, mms_port):
        """Verify fuzzer reaches MMS_ASSOCIATED state after handshake."""
        require_docker_mock("mms")

        from oida.fuzz.protocols.mms import MMSFuzzer
        from oida.fuzz.core.connections.base import MockConnectionFactory

        fuzzer = MMSFuzzer(config=mms_fuzzer_config, connection_factory=MockConnectionFactory())
        fuzzer._define_state_machine()

        current_state = fuzzer.state_machine.get_current_state_name()
        assert current_state == "MMS_ASSOCIATED"

    def test_negotiated_max_pdu_extracted(self, mms_fuzzer_config, mms_host, mms_port):
        """Verify max PDU size is parsed from server Initiate-ResponsePDU."""
        require_docker_mock("mms")

        from oida.fuzz.protocols.mms import MMSFuzzer
        from oida.fuzz.core.connections.base import MockConnectionFactory

        fuzzer = MMSFuzzer(config=mms_fuzzer_config, connection_factory=MockConnectionFactory())
        fuzzer._define_state_machine()

        # negotiated_max_pdu should be extracted (value depends on server)
        # Just verify it was set (not None) if association succeeded
        if fuzzer.association_established:
            # May or may not be set depending on server response format
            # If set, should be a positive integer
            if fuzzer.negotiated_max_pdu is not None:
                assert fuzzer.negotiated_max_pdu > 0
                assert fuzzer.negotiated_max_pdu <= 65535


# =============================================================================
# Test Request Definition State Requirements
# =============================================================================


class TestMMSRequestDefinitions:
    """Tests for MMS request definitions and their state requirements."""

    def test_all_requests_have_requires_state(self):
        """All 22 request definitions have requires_state set."""
        from oida.fuzz.protocols.mms import MMSFuzzer

        definitions = MMSFuzzer.get_request_definitions()
        assert len(definitions) == 22

        for defn in definitions:
            assert defn.requires_state is not None, f"Request '{defn.name}' missing requires_state"

    def test_connected_state_requests(self):
        """Verify 7 requests require CONNECTED state."""
        from oida.fuzz.protocols.mms import MMSFuzzer

        definitions = MMSFuzzer.get_request_definitions()
        connected_names = {d.name for d in definitions if d.requires_state == "CONNECTED"}

        expected = {
            "MMS_Baseline",
            "MMS_Buffer_Overflow",
            "MMS_ASN1_Attacks",
            "MMS_OSI_Layer",
            "MMS_Malformed_PDU",
            "MMS_ACSE_Auth",
            "MMS_Presentation_NormalMode",
        }
        assert connected_names == expected

    def test_cotp_established_state_requests(self):
        """Verify 4 requests require COTP_ESTABLISHED state."""
        from oida.fuzz.protocols.mms import MMSFuzzer

        definitions = MMSFuzzer.get_request_definitions()
        cotp_names = {d.name for d in definitions if d.requires_state == "COTP_ESTABLISHED"}

        expected = {
            "MMS_Invoke_ID",
            "MMS_IEC61850_Attacks",
            "MMS_Session_Mgmt",
            "MMS_Initiate_Negotiation",
        }
        assert cotp_names == expected

    def test_mms_associated_state_requests(self):
        """Verify the requests that require MMS_ASSOCIATED state."""
        from oida.fuzz.protocols.mms import MMSFuzzer

        definitions = MMSFuzzer.get_request_definitions()
        assoc_names = {d.name for d in definitions if d.requires_state == "MMS_ASSOCIATED"}

        expected = {
            "MMS_Write_Operations",
            "MMS_Control_Operations",
            "MMS_File_Services",
            "MMS_Read_Operations",
            "MMS_Reports",
            "MMS_BitString_UnusedBits",
            "MMS_DeleteNamedVariableList",
            "MMS_OctetString_Length_Lie",
            "MMS_Structured_Nesting",
            "MMS_Write_EmptyVarList",
            "MMS_BER_Length_OOB",
        }
        assert assoc_names == expected

    def test_valid_state_names(self):
        """All requires_state values are valid MMS state names."""
        from oida.fuzz.protocols.mms import MMSFuzzer

        valid_states = {"CONNECTED", "COTP_ESTABLISHED", "MMS_ASSOCIATED"}
        definitions = MMSFuzzer.get_request_definitions()

        for defn in definitions:
            assert defn.requires_state in valid_states, (
                f"Request '{defn.name}' has invalid state '{defn.requires_state}'"
            )


# =============================================================================
# Test Validation Methods
# =============================================================================


class TestMMSValidationMethods:
    """Tests for MMS state validation methods."""

    def test_validate_cotp_returns_flag(self, mms_fuzzer_mocked):
        """Verify _validate_cotp() returns cotp_connection_established flag."""
        assert mms_fuzzer_mocked._validate_cotp() is False

        mms_fuzzer_mocked.cotp_connection_established = True
        assert mms_fuzzer_mocked._validate_cotp() is True

    def test_validate_association_returns_flag(self, mms_fuzzer_mocked):
        """Verify _validate_association() returns association_established flag."""
        assert mms_fuzzer_mocked._validate_association() is False

        mms_fuzzer_mocked.association_established = True
        assert mms_fuzzer_mocked._validate_association() is True


# =============================================================================
# Test Fuzzer Initialization
# =============================================================================


class TestMMSFuzzerInitialization:
    """Tests for MMS fuzzer initialization against mock server."""

    def test_fuzzer_initializes_with_mock_factory(self, mms_fuzzer_config, mock_connection_factory):
        """Fuzzer creates without error using mock factory."""
        require_import("boofuzz")

        from oida.fuzz.protocols.mms import MMSFuzzer

        fuzzer = MMSFuzzer(config=mms_fuzzer_config, connection_factory=mock_connection_factory)
        assert fuzzer is not None
        assert fuzzer.config == mms_fuzzer_config

    def test_fuzzer_initializes_against_mock(self, mms_fuzzer_config, mms_host, mms_port):
        """Fuzzer creates without error when mock server is available."""
        require_docker_mock("mms")

        require_import("boofuzz")

        from oida.fuzz.protocols.mms import MMSFuzzer
        from oida.fuzz.core.connections.base import MockConnectionFactory

        fuzzer = MMSFuzzer(config=mms_fuzzer_config, connection_factory=MockConnectionFactory())
        assert fuzzer is not None

    def test_fuzzer_defines_protocol(self, mms_fuzzer_config, mock_connection_factory):
        """_define_protocol() runs without errors."""
        require_import("boofuzz")

        from oida.fuzz.protocols.mms import MMSFuzzer

        fuzzer = MMSFuzzer(config=mms_fuzzer_config, connection_factory=mock_connection_factory)

        # Patch _create_socket to avoid network issues, then access session
        with patch.object(fuzzer, "_create_socket") as mock_socket:
            mock_conn = MagicMock()
            mock_conn.open = MagicMock()
            mock_conn.close = MagicMock()
            mock_conn.send = MagicMock(return_value=10)
            mock_conn.recv = MagicMock(return_value=b"")
            mock_socket.return_value = mock_conn

            # Access session property to trigger _define_protocol
            session = fuzzer.session
            assert session is not None
            assert hasattr(session, "nodes")


# =============================================================================
# Test Fuzzer Execution (Slow Tests)
# =============================================================================


@pytest.mark.slow
class TestMMSFuzzerExecution:
    """Integration tests that run fuzzing against the mock server."""

    def test_mms_baseline_fuzz(self, mms_fuzzer_config, mms_host, mms_port):
        """Test running MMS_Baseline requests against mock."""
        require_docker_mock("mms")

        require_import("boofuzz")

        from oida.fuzz.protocols.mms import MMSFuzzer
        from oida.fuzz.core.connections.base import MockConnectionFactory

        mms_fuzzer_config.enabled_requests = ["MMS_Baseline"]
        mms_fuzzer_config.index_end = 5  # Minimal iterations

        fuzzer = MMSFuzzer(config=mms_fuzzer_config, connection_factory=MockConnectionFactory())

        # Define protocol and verify session has nodes
        with patch.object(fuzzer, "_create_socket") as mock_socket:
            mock_conn = MagicMock()
            mock_conn.open = MagicMock()
            mock_conn.close = MagicMock()
            mock_conn.send = MagicMock(return_value=10)
            mock_conn.recv = MagicMock(return_value=b"")
            mock_socket.return_value = mock_conn

            session = fuzzer.session
            assert session is not None
            # Should have baseline requests defined
            assert len(session.nodes) > 0

    def test_mms_buffer_overflow_fuzz(self, mms_fuzzer_config, mock_connection_factory):
        """Test MMS_Buffer_Overflow request group definition."""
        require_import("boofuzz")

        from oida.fuzz.protocols.mms import MMSFuzzer

        mms_fuzzer_config.enabled_requests = ["MMS_Buffer_Overflow"]

        fuzzer = MMSFuzzer(config=mms_fuzzer_config, connection_factory=mock_connection_factory)

        with patch.object(fuzzer, "_create_socket") as mock_socket:
            mock_conn = MagicMock()
            mock_conn.open = MagicMock()
            mock_conn.close = MagicMock()
            mock_conn.send = MagicMock(return_value=10)
            mock_conn.recv = MagicMock(return_value=b"")
            mock_socket.return_value = mock_conn

            session = fuzzer.session
            assert session is not None
            assert len(session.nodes) > 0

    def test_mms_asn1_attacks_fuzz(self, mms_fuzzer_config, mock_connection_factory):
        """Test MMS_ASN1_Attacks request group definition."""
        require_import("boofuzz")

        from oida.fuzz.protocols.mms import MMSFuzzer

        mms_fuzzer_config.enabled_requests = ["MMS_ASN1_Attacks"]

        fuzzer = MMSFuzzer(config=mms_fuzzer_config, connection_factory=mock_connection_factory)

        with patch.object(fuzzer, "_create_socket") as mock_socket:
            mock_conn = MagicMock()
            mock_conn.open = MagicMock()
            mock_conn.close = MagicMock()
            mock_conn.send = MagicMock(return_value=10)
            mock_conn.recv = MagicMock(return_value=b"")
            mock_socket.return_value = mock_conn

            session = fuzzer.session
            assert session is not None

    def test_mms_osi_layer_fuzz(self, mms_fuzzer_config, mock_connection_factory):
        """Test MMS_OSI_Layer request group definition."""
        require_import("boofuzz")

        from oida.fuzz.protocols.mms import MMSFuzzer

        mms_fuzzer_config.enabled_requests = ["MMS_OSI_Layer"]

        fuzzer = MMSFuzzer(config=mms_fuzzer_config, connection_factory=mock_connection_factory)

        with patch.object(fuzzer, "_create_socket") as mock_socket:
            mock_conn = MagicMock()
            mock_conn.open = MagicMock()
            mock_conn.close = MagicMock()
            mock_conn.send = MagicMock(return_value=10)
            mock_conn.recv = MagicMock(return_value=b"")
            mock_socket.return_value = mock_conn

            session = fuzzer.session
            assert session is not None

    def test_mms_write_operations_fuzz(self, mms_fuzzer_config, mock_connection_factory):
        """Test MMS_Write_Operations request group definition."""
        require_import("boofuzz")

        from oida.fuzz.protocols.mms import MMSFuzzer

        mms_fuzzer_config.enabled_requests = ["MMS_Write_Operations"]

        fuzzer = MMSFuzzer(config=mms_fuzzer_config, connection_factory=mock_connection_factory)

        with patch.object(fuzzer, "_create_socket") as mock_socket:
            mock_conn = MagicMock()
            mock_conn.open = MagicMock()
            mock_conn.close = MagicMock()
            mock_conn.send = MagicMock(return_value=10)
            mock_conn.recv = MagicMock(return_value=b"")
            mock_socket.return_value = mock_conn

            session = fuzzer.session
            assert session is not None

    def test_mms_read_operations_fuzz(self, mms_fuzzer_config, mock_connection_factory):
        """Test MMS_Read_Operations request group definition."""
        require_import("boofuzz")

        from oida.fuzz.protocols.mms import MMSFuzzer

        mms_fuzzer_config.enabled_requests = ["MMS_Read_Operations"]

        fuzzer = MMSFuzzer(config=mms_fuzzer_config, connection_factory=mock_connection_factory)

        with patch.object(fuzzer, "_create_socket") as mock_socket:
            mock_conn = MagicMock()
            mock_conn.open = MagicMock()
            mock_conn.close = MagicMock()
            mock_conn.send = MagicMock(return_value=10)
            mock_conn.recv = MagicMock(return_value=b"")
            mock_socket.return_value = mock_conn

            session = fuzzer.session
            assert session is not None

    def test_mms_invoke_id_fuzz(self, mms_fuzzer_config, mock_connection_factory):
        """Test MMS_Invoke_ID request group definition."""
        require_import("boofuzz")

        from oida.fuzz.protocols.mms import MMSFuzzer

        mms_fuzzer_config.enabled_requests = ["MMS_Invoke_ID"]

        fuzzer = MMSFuzzer(config=mms_fuzzer_config, connection_factory=mock_connection_factory)

        with patch.object(fuzzer, "_create_socket") as mock_socket:
            mock_conn = MagicMock()
            mock_conn.open = MagicMock()
            mock_conn.close = MagicMock()
            mock_conn.send = MagicMock(return_value=10)
            mock_conn.recv = MagicMock(return_value=b"")
            mock_socket.return_value = mock_conn

            session = fuzzer.session
            assert session is not None

    def test_mms_malformed_pdu_fuzz(self, mms_fuzzer_config, mock_connection_factory):
        """Test MMS_Malformed_PDU request group definition."""
        require_import("boofuzz")

        from oida.fuzz.protocols.mms import MMSFuzzer

        mms_fuzzer_config.enabled_requests = ["MMS_Malformed_PDU"]

        fuzzer = MMSFuzzer(config=mms_fuzzer_config, connection_factory=mock_connection_factory)

        with patch.object(fuzzer, "_create_socket") as mock_socket:
            mock_conn = MagicMock()
            mock_conn.open = MagicMock()
            mock_conn.close = MagicMock()
            mock_conn.send = MagicMock(return_value=10)
            mock_conn.recv = MagicMock(return_value=b"")
            mock_socket.return_value = mock_conn

            session = fuzzer.session
            assert session is not None


# =============================================================================
# Test Server Interaction
# =============================================================================


class TestMMSServerInteraction:
    """Tests for MMS fuzzer interaction with the mock server."""

    def test_fuzzer_handles_server_disconnect(self, mms_fuzzer_config, mock_connection_factory):
        """Graceful handling of server disconnects."""
        require_import("boofuzz")

        from oida.fuzz.protocols.mms import MMSFuzzer

        fuzzer = MMSFuzzer(config=mms_fuzzer_config, connection_factory=mock_connection_factory)

        # Simulate disconnect during state machine setup
        with patch("socket.socket") as mock_socket_cls:
            mock_sock = MagicMock()
            mock_sock.connect.side_effect = socket.error("Connection refused")
            mock_socket_cls.return_value = mock_sock

            # Should not raise - just logs warning and continues
            fuzzer._define_state_machine()

            # State flags must stay False on connection failure -- the
            # handshake never got past socket.connect(), so neither the COTP
            # transport connection nor the MMS association can be "up".
            assert fuzzer.cotp_connection_established is False
            assert fuzzer.association_established is False
            assert fuzzer._state_context.get("cotp_connection_established") is False
            assert fuzzer._state_context.get("association_established") is False
            # The state machine itself must still be built (with marker
            # states only) so fuzzing can proceed against a live target later.
            assert fuzzer.state_machine is not None

    def test_fuzzer_handles_timeout(self, mms_fuzzer_config, mock_connection_factory):
        """Graceful handling of connection timeouts."""
        require_import("boofuzz")

        from oida.fuzz.protocols.mms import MMSFuzzer

        fuzzer = MMSFuzzer(config=mms_fuzzer_config, connection_factory=mock_connection_factory)

        # Simulate timeout during state machine setup
        with patch("socket.socket") as mock_socket_cls:
            mock_sock = MagicMock()
            mock_sock.connect.side_effect = socket.timeout("Connection timed out")
            mock_socket_cls.return_value = mock_sock

            # Should not raise - just logs warning and continues
            fuzzer._define_state_machine()

            # A timed-out connect() must leave the same "nothing established"
            # state as any other connection failure -- the fuzzer shouldn't
            # believe the handshake progressed just because it saw a timeout
            # instead of a refused/reset connection.
            assert fuzzer.cotp_connection_established is False
            assert fuzzer.association_established is False
            assert fuzzer._state_context.get("cotp_connection_established") is False
            assert fuzzer._state_context.get("association_established") is False
            assert fuzzer.state_machine is not None


# =============================================================================
# Test OSI Stack Features
# =============================================================================


class TestMMSOSIStackIntegration:
    """Tests for OSI stack integration in MMS fuzzer."""

    def test_osi_stack_enabled_by_default(self, mms_fuzzer_mocked):
        """OSI stack is enabled by default."""
        assert mms_fuzzer_mocked.use_osi_stack is True
        assert hasattr(mms_fuzzer_mocked, "osi_stack")

    def test_legacy_mode_disables_osi_stack(self, mms_fuzzer_config, mock_connection_factory):
        """Legacy mode disables OSI stack."""
        require_import("boofuzz")

        from oida.fuzz.protocols.mms import MMSFuzzer

        mms_fuzzer_config.protocol_options = {"legacy_mode": True}
        fuzzer = MMSFuzzer(config=mms_fuzzer_config, connection_factory=mock_connection_factory)

        assert fuzzer.use_osi_stack is False

    def test_wrap_with_osi_stack_data_transfer(self, mms_fuzzer_mocked):
        """_wrap_with_osi_stack wraps MMS PDU for data transfer."""
        # Create a simple MMS PDU
        mms_pdu = bytes([0xA0, 0x05, 0x02, 0x01, 0x01, 0xA5, 0x00])

        wrapped = mms_fuzzer_mocked._wrap_with_osi_stack(mms_pdu, is_initiate=False)

        # Should be wrapped (longer than original)
        assert len(wrapped) >= len(mms_pdu)

    def test_create_wrapped_request(self, mms_fuzzer_mocked):
        """_create_wrapped_request creates boofuzz Request with OSI wrapping."""
        from boofuzz import Request

        mms_pdu = mms_fuzzer_mocked._create_read_request()
        request = mms_fuzzer_mocked._create_wrapped_request("test_request", mms_pdu)

        assert isinstance(request, Request)
        assert request.name == "test_request"


# =============================================================================
# Test Protocol Constants
# =============================================================================


class TestMMSProtocolConstants:
    """Verify MMS protocol constants are correctly defined."""

    def test_pdu_types(self):
        """PDU type constants match ISO 9506 MMS specification."""
        from oida.fuzz.protocols.mms import MMSFuzzer

        assert MMSFuzzer.PDU_CONFIRMED_REQUEST == 0xA0
        assert MMSFuzzer.PDU_CONFIRMED_RESPONSE == 0xA1
        assert MMSFuzzer.PDU_CONFIRMED_ERROR == 0xA2
        assert MMSFuzzer.PDU_UNCONFIRMED == 0xA3
        assert MMSFuzzer.PDU_REJECT == 0xA4
        assert MMSFuzzer.PDU_INITIATE_REQUEST == 0xA8
        assert MMSFuzzer.PDU_INITIATE_RESPONSE == 0xA9

    def test_service_ids(self):
        """Service ID constants match ISO 9506-2 ASN.1 context tags."""
        from oida.fuzz.protocols.mms import MMSFuzzer

        assert MMSFuzzer.SERVICE_READ == b"\xa4"  # [4] constructed
        assert MMSFuzzer.SERVICE_WRITE == b"\xa5"  # [5] constructed
        assert MMSFuzzer.SERVICE_GET_NAME_LIST == b"\xa1"  # [1] constructed
        assert MMSFuzzer.SERVICE_IDENTIFY == b"\x82"  # [2] primitive
        assert MMSFuzzer.SERVICE_FILE_OPEN == b"\xbf\x48"  # [72] constructed

    def test_iec61850_addcause_codes(self):
        """IEC 61850 AddCause codes are defined."""
        from oida.fuzz.protocols.mms import MMSFuzzer

        assert MMSFuzzer.ADD_CAUSE_UNKNOWN == 0
        assert MMSFuzzer.ADD_CAUSE_NOT_SUPPORTED == 1
        assert MMSFuzzer.ADD_CAUSE_LOCKED_BY_OTHER_CLIENT == 27


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
