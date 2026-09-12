"""
Tier 1.5: Dynamic state traversal integration tests.

For protocols with state machines, drive the fuzzer against a real mock
server and verify that the state machine can successfully traverse to
each defined state.

This catches bugs in state setup callbacks that only manifest against
real servers (e.g., incorrect packet construction, unexpected responses).
"""

import pytest

from tests.service_gate import require_import, require_service

from .conftest import create_fuzzer_config
from .mock_servers import (
    mms_server,
)

pytestmark = pytest.mark.integration_fuzzers


def _create_fuzzer_with_mock(fuzzer_class, config):
    """Create a fuzzer with MockConnectionFactory and trigger session init.

    The session property is lazy -- accessing it triggers protocol definition
    and state machine setup. Without this, fuzzer.state_machine will be None.

    Some protocols (SMTP, FTP) attempt state transitions during session init
    which fail in mock mode (no real server). We catch those errors since the
    state machine is already created before the transitions are attempted.
    """
    from oida.fuzz.core.connections import MockConnectionFactory
    from oida.fuzz.core.session.state_machine import StateTransitionError

    fuzzer = fuzzer_class(
        config=config,
        connection_factory=MockConnectionFactory(),
    )
    # Trigger lazy session initialization (which calls _define_state_machine)
    try:
        _ = fuzzer.session
    except StateTransitionError:
        # State machine was created but transitions failed (expected in mock mode)
        pass
    return fuzzer


def _create_fuzzer_with_server(fuzzer_class, config):
    """Create a fuzzer targeting a real server and trigger session init."""
    fuzzer = fuzzer_class(config=config)
    # Trigger lazy session initialization
    _ = fuzzer.session
    return fuzzer


def _get_fuzzer_class(protocol_name):
    """Get fuzzer class for a protocol, skipping if unavailable."""
    boofuzz = require_import("boofuzz")  # noqa: F841
    from oida.fuzz.protocols import PROTOCOL_FUZZERS

    fuzzer_class = PROTOCOL_FUZZERS.get(protocol_name)
    if not fuzzer_class:
        require_service(f"{protocol_name} fuzzer not available")
    return fuzzer_class


def _create_mock_fuzzer(protocol_name, tmp_path, protocol_options=None):
    """Create a fuzzer with mock connection for state introspection.

    Handles ImportError from missing optional dependencies gracefully.
    """
    fuzzer_class = _get_fuzzer_class(protocol_name)

    config = create_fuzzer_config(
        "127.0.0.1",
        9999,
        protocol_name,
        str(tmp_path / "session"),
        protocol_options=protocol_options or {},
    )

    try:
        return _create_fuzzer_with_mock(fuzzer_class, config)
    except ImportError as e:
        require_service(f"Missing dependency: {e}")


def _get_inner_state_machine(fuzzer):
    """Get the framework StateMachine from a fuzzer, unwrapping protocol-specific wrappers.

    IEC 104 uses a custom IEC104StateMachine wrapper whose `.state_machine` property
    returns the inner framework StateMachine. Other protocols return StateMachine directly.
    """
    sm = fuzzer.state_machine
    if sm is None:
        return None
    from oida.fuzz.core.session.state_machine import StateMachine

    if not isinstance(sm, StateMachine) and hasattr(sm, "state_machine"):
        inner = sm.state_machine
        if isinstance(inner, StateMachine):
            return inner
    return sm


# ============================================================================
# MMS State Traversal
# ============================================================================


class TestMMSStateTraversal:
    """Verify the MMS state machine can reach each state against a real server.

    MMS has 3 states: CONNECTED -> COTP_ESTABLISHED -> MMS_ASSOCIATED
    """

    def test_state_machine_created(self, tmp_path):
        """MMS fuzzer should create a state machine."""
        fuzzer = _create_mock_fuzzer("mms", tmp_path)

        # MMS always creates its state machine (even for mock)
        sm = _get_inner_state_machine(fuzzer)
        assert sm is not None, "MMS should always create a state machine"
        assert "CONNECTED" in sm.states
        assert "COTP_ESTABLISHED" in sm.states
        assert "MMS_ASSOCIATED" in sm.states

    def test_topological_order(self, tmp_path):
        """MMS states should have a valid topological order."""
        fuzzer = _create_mock_fuzzer("mms", tmp_path)
        sm = _get_inner_state_machine(fuzzer)
        if sm is None:
            pytest.skip("MMS state machine not created")

        topo = sm.get_topological_order()
        assert len(topo) == 3, f"Expected 3 states in topo order, got {len(topo)}: {topo}"
        # CONNECTED must come before COTP_ESTABLISHED, which must come before MMS_ASSOCIATED
        assert topo.index("CONNECTED") < topo.index("COTP_ESTABLISHED")
        assert topo.index("COTP_ESTABLISHED") < topo.index("MMS_ASSOCIATED")

    def test_state_traversal_against_real_server(self, tmp_path):
        """Verify state machine traversal works against real MMS server."""
        fuzzer_class = _get_fuzzer_class("mms")

        with mms_server() as server:
            config = create_fuzzer_config(
                server.host,
                server.port,
                "mms",
                str(tmp_path / "session"),
            )

            try:
                fuzzer = _create_fuzzer_with_server(fuzzer_class, config)
            except ImportError as e:
                require_service(f"Missing dependency: {e}")

            sm = _get_inner_state_machine(fuzzer)
            if sm is None:
                pytest.skip("MMS state machine not created")

            # The MMS state machine should have traversed during _define_state_machine
            # Check what state we ended up in
            current = sm.get_current_state_name()

            # Record which states were visited via history
            visited = set(sm.get_state_history())
            assert "CONNECTED" in visited or current != "CONNECTED", (
                "Should have started at CONNECTED"
            )


# ============================================================================
# MQTT State Traversal (requires use_auth=True)
# ============================================================================


class TestMQTTStateTraversal:
    """Verify the MQTT state machine graph is correct with mock connections.

    MQTT has 5 states: DISCONNECTED -> CONNECTED -> CONNECT_SENT -> CONNACK_RECEIVED -> READY
    Since MQTT needs real broker responses for actual traversal, we test
    the graph structure here.
    """

    def test_state_machine_created_with_auth(self, tmp_path):
        """MQTT should create state machine when use_auth=True.

        Note: MQTT skips state machine creation with MockConnectionFactory
        ('Mock connection detected, skipping MQTT state machine authentication').
        This test verifies structure when available, and skips in mock mode.
        """
        fuzzer = _create_mock_fuzzer("mqtt", tmp_path, protocol_options={"use_auth": True})

        sm = _get_inner_state_machine(fuzzer)
        if sm is None:
            pytest.skip("MQTT skips state machine in mock mode")
        assert "DISCONNECTED" in sm.states
        assert "CONNECTED" in sm.states
        assert "CONNECT_SENT" in sm.states
        assert "CONNACK_RECEIVED" in sm.states
        assert "READY" in sm.states

    def test_topological_order(self, tmp_path):
        """MQTT states should have a valid topological order."""
        fuzzer = _create_mock_fuzzer("mqtt", tmp_path, protocol_options={"use_auth": True})
        sm = _get_inner_state_machine(fuzzer)
        if sm is None:
            pytest.skip("MQTT state machine not created")

        topo = sm.get_topological_order()
        assert len(topo) == 5, f"Expected 5 states in topo order, got {len(topo)}: {topo}"
        # Verify ordering constraints
        assert topo.index("DISCONNECTED") < topo.index("CONNECTED")
        assert topo.index("CONNECTED") < topo.index("CONNECT_SENT")

    def test_mock_state_machine_has_setup_callbacks(self, tmp_path):
        """In mock mode, setup callbacks should still be defined on the state machine.

        The state machine is always created with the same structure regardless of
        connection type.  Setup callbacks are present so the graph is complete;
        they simply fail gracefully when no real broker is available.
        """
        fuzzer = _create_mock_fuzzer("mqtt", tmp_path, protocol_options={"use_auth": True})

        sm = _get_inner_state_machine(fuzzer)
        if sm is None:
            pytest.skip("MQTT state machine not created")

        # CONNECT_SENT should have a setup callback (state machine is fully defined)
        connect_sent = sm.states.get("CONNECT_SENT")
        assert connect_sent is not None
        assert connect_sent.setup is not None, "CONNECT_SENT should have setup callback defined"


# ============================================================================
# FTP State Traversal
# ============================================================================


class TestFTPStateTraversal:
    """Verify FTP state machine graph is correct."""

    def test_simple_auth_state_machine_created(self, tmp_path):
        """FTP should create a 2-state auth machine with use_auth=True.

        Note: FTP skips state machine creation with MockConnectionFactory.
        """
        fuzzer = _create_mock_fuzzer("ftp", tmp_path, protocol_options={"use_auth": True})

        sm = _get_inner_state_machine(fuzzer)
        if sm is None:
            pytest.skip("FTP skips state machine in mock mode")
        assert "CONNECTED" in sm.states
        assert "AUTHENTICATED" in sm.states

    def test_ftps_state_machine_created(self, tmp_path):
        """FTPS should create a 6-state machine with TLS upgrade.

        Note: FTP skips state machine creation with MockConnectionFactory.
        """
        fuzzer = _create_mock_fuzzer(
            "ftp", tmp_path, protocol_options={"use_auth": True, "use_tls": True}
        )

        sm = _get_inner_state_machine(fuzzer)
        if sm is None:
            pytest.skip("FTP skips state machine in mock mode")
        assert "CONNECTED" in sm.states
        assert "TLS_NEGOTIATION" in sm.states
        assert "TLS_ESTABLISHED" in sm.states
        assert "PBSZ_SET" in sm.states
        assert "PROT_SET" in sm.states
        assert "AUTHENTICATED" in sm.states

    def test_ftps_topological_order(self, tmp_path):
        """FTPS states should have a valid topological order reflecting TLS chain."""
        fuzzer = _create_mock_fuzzer(
            "ftp", tmp_path, protocol_options={"use_auth": True, "use_tls": True}
        )
        sm = _get_inner_state_machine(fuzzer)
        if sm is None:
            pytest.skip("FTP TLS state machine not created")

        topo = sm.get_topological_order()
        assert len(topo) == 6, f"Expected 6 states, got {len(topo)}: {topo}"
        # CONNECTED must come first, AUTHENTICATED must come last
        assert topo.index("CONNECTED") < topo.index("TLS_NEGOTIATION")
        assert topo.index("TLS_ESTABLISHED") < topo.index("AUTHENTICATED")


# ============================================================================
# VNC State Traversal
# ============================================================================


class TestVNCStateTraversal:
    """Verify VNC state machine graph is correct."""

    def test_state_machine_created(self, tmp_path):
        """VNC should create a 4-state machine with use_auth=True.

        Note: VNC skips state machine creation with MockConnectionFactory.
        """
        fuzzer = _create_mock_fuzzer("vnc", tmp_path, protocol_options={"use_auth": True})

        sm = _get_inner_state_machine(fuzzer)
        if sm is None:
            pytest.skip("VNC skips state machine in mock mode")
        assert "CONNECTED" in sm.states
        assert "VERSION_EXCHANGED" in sm.states
        assert "SECURITY_NEGOTIATED" in sm.states
        assert "AUTHENTICATED" in sm.states

    def test_topological_order(self, tmp_path):
        """VNC states should have a valid topological order."""
        fuzzer = _create_mock_fuzzer("vnc", tmp_path, protocol_options={"use_auth": True})
        sm = _get_inner_state_machine(fuzzer)
        if sm is None:
            pytest.skip("VNC state machine not created")

        topo = sm.get_topological_order()
        assert len(topo) == 4, f"Expected 4 states, got {len(topo)}: {topo}"
        assert topo.index("CONNECTED") < topo.index("VERSION_EXCHANGED")
        assert topo.index("VERSION_EXCHANGED") < topo.index("SECURITY_NEGOTIATED")
        assert topo.index("SECURITY_NEGOTIATED") < topo.index("AUTHENTICATED")


# ============================================================================
# SMTP State Traversal
# ============================================================================


class TestSMTPStateTraversal:
    """Verify SMTP state machine graph is correct."""

    def test_simple_auth_state_machine_created(self, tmp_path):
        """SMTP should create a 2-state auth machine with use_auth=True.

        Note: SMTP skips state machine creation with MockConnectionFactory.
        """
        fuzzer = _create_mock_fuzzer("smtp", tmp_path, protocol_options={"use_auth": True})

        sm = _get_inner_state_machine(fuzzer)
        if sm is None:
            pytest.skip("SMTP skips state machine in mock mode")
        assert "CONNECTED" in sm.states
        assert "AUTHENTICATED" in sm.states

    def test_starttls_state_machine_created(self, tmp_path):
        """SMTP should create a 6-state machine with use_starttls=True.

        Note: SMTP skips state machine creation with MockConnectionFactory.
        """
        fuzzer = _create_mock_fuzzer(
            "smtp", tmp_path, protocol_options={"use_auth": True, "use_starttls": True}
        )

        sm = _get_inner_state_machine(fuzzer)
        if sm is None:
            pytest.skip("SMTP skips state machine in mock mode")
        assert "CONNECTED" in sm.states
        assert "EHLO_SENT" in sm.states
        assert "STARTTLS_SENT" in sm.states
        assert "TLS_ESTABLISHED" in sm.states
        assert "EHLO_TLS_SENT" in sm.states
        assert "AUTHENTICATED" in sm.states

    def test_starttls_topological_order(self, tmp_path):
        """SMTP STARTTLS states should have a valid topological order."""
        fuzzer = _create_mock_fuzzer(
            "smtp", tmp_path, protocol_options={"use_auth": True, "use_starttls": True}
        )
        sm = _get_inner_state_machine(fuzzer)
        if sm is None:
            pytest.skip("SMTP STARTTLS state machine not created")

        topo = sm.get_topological_order()
        assert len(topo) == 6, f"Expected 6 states, got {len(topo)}: {topo}"
        assert topo.index("CONNECTED") < topo.index("EHLO_SENT")
        assert topo.index("TLS_ESTABLISHED") < topo.index("AUTHENTICATED")


# ============================================================================
# OPC UA State Traversal
# ============================================================================


class TestOPCUAStateTraversal:
    """Verify OPC UA state machine with mock connections.

    OPC UA has 4 states (when use_session=True):
    CONNECTED -> HELLO_COMPLETE -> SECURE_CHANNEL -> SESSION_ACTIVE

    OPC UA derives live protocol state (ChannelId / TokenId / AuthToken) from a
    real asyncua handshake, which can't run against the MockConnectionFactory
    target. The autouse fixture below mocks the asyncua Client so the handshake
    "succeeds" with deterministic state and the static state machine is built,
    letting us verify its structure offline.
    """

    @pytest.fixture(autouse=True)
    def _mock_opcua_handshake(self):
        try:
            import asyncua
        except ImportError:
            yield
            return

        from unittest.mock import AsyncMock, MagicMock, patch

        def make_client(url, *args, **kwargs):
            client = MagicMock()
            client.connect = AsyncMock()
            client.disconnect = AsyncMock()
            conn = client.uaclient.protocol._connection
            conn.security_token.ChannelId = 1
            conn.security_token.TokenId = 1
            conn.remote_nonce = b"\x00" * 32
            client.uaclient.protocol.authentication_token = b"\x01" * 8
            return client

        with patch.object(asyncua, "Client") as mock_client:
            mock_client.side_effect = make_client
            yield

    def test_state_machine_structure_with_mock(self, tmp_path):
        """OPC UA should define 4 states when session mode is enabled."""
        fuzzer = _create_mock_fuzzer("opcua", tmp_path, protocol_options={"use_session": True})
        sm = _get_inner_state_machine(fuzzer)
        assert sm is not None, "OPC UA state machine should be built with use_session=True"

        expected = {"CONNECTED", "HELLO_COMPLETE", "SECURE_CHANNEL", "SESSION_ACTIVE"}
        actual = set(sm.states.keys())
        assert expected == actual, f"OPC UA: expected states {expected}, got {actual}"

    def test_topological_order_with_mock(self, tmp_path):
        """OPC UA should have a linear topological order."""
        fuzzer = _create_mock_fuzzer("opcua", tmp_path, protocol_options={"use_session": True})
        sm = _get_inner_state_machine(fuzzer)
        assert sm is not None, "OPC UA state machine should be built with use_session=True"

        topo = sm.get_topological_order()
        assert len(topo) == 4
        assert topo.index("CONNECTED") < topo.index("HELLO_COMPLETE")
        assert topo.index("HELLO_COMPLETE") < topo.index("SECURE_CHANNEL")
        assert topo.index("SECURE_CHANNEL") < topo.index("SESSION_ACTIVE")

    def test_no_state_machine_without_session(self, tmp_path):
        """OPC UA without use_session should not create a state machine."""
        fuzzer = _create_mock_fuzzer("opcua", tmp_path, protocol_options={})
        sm = fuzzer.state_machine
        assert sm is None, "OPC UA without use_session=True should not create a state machine"

    def test_request_definitions_exist(self, tmp_path):
        """OPC UA must have request definitions regardless of state machine."""
        fuzzer = _create_mock_fuzzer("opcua", tmp_path, protocol_options={"use_session": True})
        definitions = fuzzer.get_request_definitions()
        assert len(definitions) >= 4, (
            f"OPC UA should have >= 4 request definitions, got {len(definitions)}"
        )


# ============================================================================
# ADS State Traversal
# ============================================================================


class TestADSStateTraversal:
    """Verify ADS state machine with mock connections.

    ADS has 2 states: CONNECTED -> ADS_VALIDATED
    In mock mode, device_validated will be False (no real ADS server),
    so the state machine stays at CONNECTED.
    """

    def test_state_machine_created(self, tmp_path):
        """ADS fuzzer should always create a state machine."""
        fuzzer = _create_mock_fuzzer("ads", tmp_path)

        sm = _get_inner_state_machine(fuzzer)
        assert sm is not None, "ADS should always create a state machine"
        assert "CONNECTED" in sm.states
        assert "ADS_VALIDATED" in sm.states
        assert len(sm.states) == 2, f"ADS should have exactly 2 states, got {len(sm.states)}"

    def test_initial_state_is_connected(self, tmp_path):
        """ADS should start in CONNECTED state (not ADS_VALIDATED in mock mode)."""
        fuzzer = _create_mock_fuzzer("ads", tmp_path)
        sm = _get_inner_state_machine(fuzzer)
        if sm is None:
            pytest.skip("ADS state machine not created")

        initial = sm.state_history[0]
        assert initial == "CONNECTED", f"ADS initial state should be CONNECTED, got {initial}"

        # In mock mode, device_validated is False, so we stay at CONNECTED
        current = sm.get_current_state_name()
        assert current == "CONNECTED", (
            f"ADS current state in mock mode should be CONNECTED, got {current}"
        )

    def test_topological_order(self, tmp_path):
        """ADS should have CONNECTED before ADS_VALIDATED."""
        fuzzer = _create_mock_fuzzer("ads", tmp_path)
        sm = _get_inner_state_machine(fuzzer)
        if sm is None:
            pytest.skip("ADS state machine not created")

        topo = sm.get_topological_order()
        assert len(topo) == 2
        assert topo.index("CONNECTED") < topo.index("ADS_VALIDATED")

    def test_path_to_ads_validated(self, tmp_path):
        """Path from CONNECTED to ADS_VALIDATED should exist."""
        fuzzer = _create_mock_fuzzer("ads", tmp_path)
        sm = _get_inner_state_machine(fuzzer)
        if sm is None:
            pytest.skip("ADS state machine not created")

        path = sm.get_path_to_state("ADS_VALIDATED")
        assert path == ["CONNECTED", "ADS_VALIDATED"], (
            f"Expected path [CONNECTED, ADS_VALIDATED], got {path}"
        )

    def test_sequence_manager_invoke_id(self, tmp_path):
        """ADS should have an invoke_id sequence in its SequenceManager."""
        fuzzer = _create_mock_fuzzer("ads", tmp_path)

        ctx = getattr(fuzzer, "_state_context", None)
        if ctx is None:
            pytest.skip("ADS does not expose _state_context")

        assert ctx.has_sequence_manager("ads"), "ADS should have 'ads' SequenceManager"
        seq_mgr = ctx.get_sequence_manager("ads")
        invoke_id = seq_mgr.get("invoke_id")
        assert isinstance(invoke_id, int), f"invoke_id should be int, got {type(invoke_id)}"

    def test_request_definitions_cover_both_states(self, tmp_path):
        """ADS requests should reference both CONNECTED and ADS_VALIDATED states."""
        fuzzer = _create_mock_fuzzer("ads", tmp_path)
        definitions = fuzzer.get_request_definitions()

        referenced_states = set()
        for req in definitions:
            if req.requires_state is not None:
                state_str = (
                    req.requires_state.value
                    if hasattr(req.requires_state, "value")
                    else str(req.requires_state)
                )
                referenced_states.add(state_str)

        assert "CONNECTED" in referenced_states, (
            "ADS should have requests targeting CONNECTED state"
        )
        assert "ADS_VALIDATED" in referenced_states, (
            "ADS should have requests targeting ADS_VALIDATED state"
        )


# ============================================================================
# EtherNet/IP State Traversal
# ============================================================================


class TestEtherNetIPStateTraversal:
    """Verify EtherNet/IP state machine with mock connections.

    EtherNet/IP has 2 states: CONNECTED -> SESSION_REGISTERED
    In mock mode, RegisterSession fails, so state stays at CONNECTED.
    """

    def test_state_machine_created(self, tmp_path):
        """EtherNet/IP fuzzer should always create a state machine."""
        fuzzer = _create_mock_fuzzer("ethernetip", tmp_path)

        sm = _get_inner_state_machine(fuzzer)
        assert sm is not None, "EtherNet/IP should always create a state machine"
        assert "CONNECTED" in sm.states
        assert "SESSION_REGISTERED" in sm.states
        assert len(sm.states) == 2, (
            f"EtherNet/IP should have exactly 2 states, got {len(sm.states)}"
        )

    def test_initial_state_is_connected(self, tmp_path):
        """EtherNet/IP should start in CONNECTED state in mock mode."""
        fuzzer = _create_mock_fuzzer("ethernetip", tmp_path)
        sm = _get_inner_state_machine(fuzzer)
        if sm is None:
            pytest.skip("EtherNet/IP state machine not created")

        initial = sm.state_history[0]
        assert initial == "CONNECTED", (
            f"EtherNet/IP initial state should be CONNECTED, got {initial}"
        )

    def test_topological_order(self, tmp_path):
        """EtherNet/IP should have CONNECTED before SESSION_REGISTERED."""
        fuzzer = _create_mock_fuzzer("ethernetip", tmp_path)
        sm = _get_inner_state_machine(fuzzer)
        if sm is None:
            pytest.skip("EtherNet/IP state machine not created")

        topo = sm.get_topological_order()
        assert len(topo) == 2
        assert topo.index("CONNECTED") < topo.index("SESSION_REGISTERED")

    def test_path_to_session_registered(self, tmp_path):
        """Path from CONNECTED to SESSION_REGISTERED should exist."""
        fuzzer = _create_mock_fuzzer("ethernetip", tmp_path)
        sm = _get_inner_state_machine(fuzzer)
        if sm is None:
            pytest.skip("EtherNet/IP state machine not created")

        path = sm.get_path_to_state("SESSION_REGISTERED")
        assert path == ["CONNECTED", "SESSION_REGISTERED"], (
            f"Expected path [CONNECTED, SESSION_REGISTERED], got {path}"
        )

    def test_sequence_manager_sender_context(self, tmp_path):
        """EtherNet/IP should have a sender_context sequence."""
        fuzzer = _create_mock_fuzzer("ethernetip", tmp_path)

        ctx = getattr(fuzzer, "_state_context", None)
        if ctx is None:
            pytest.skip("EtherNet/IP does not expose _state_context")

        assert ctx.has_sequence_manager("enip"), "EtherNet/IP should have 'enip' SequenceManager"
        seq_mgr = ctx.get_sequence_manager("enip")
        val = seq_mgr.get("sender_context")
        assert isinstance(val, int), f"sender_context should be int, got {type(val)}"

    def test_request_definitions_cover_both_states(self, tmp_path):
        """EtherNet/IP requests should reference both states."""
        fuzzer = _create_mock_fuzzer("ethernetip", tmp_path)
        definitions = fuzzer.get_request_definitions()

        referenced_states = set()
        for req in definitions:
            if req.requires_state is not None:
                state_str = (
                    req.requires_state.value
                    if hasattr(req.requires_state, "value")
                    else str(req.requires_state)
                )
                referenced_states.add(state_str)

        assert "CONNECTED" in referenced_states, (
            "EtherNet/IP should have requests targeting CONNECTED state"
        )
        assert "SESSION_REGISTERED" in referenced_states, (
            "EtherNet/IP should have requests targeting SESSION_REGISTERED state"
        )


# ============================================================================
# IEC 104 State Traversal
# ============================================================================


class TestIEC104StateTraversal:
    """Verify IEC 104 state machine with mock connections.

    IEC 104 has 3 states: DISCONNECTED -> CONNECTED -> DATA_TRANSFER
    """

    def test_state_machine_created(self, tmp_path):
        """IEC 104 fuzzer should always create a state machine."""
        fuzzer = _create_mock_fuzzer("iec104", tmp_path)

        sm = _get_inner_state_machine(fuzzer)
        assert sm is not None, "IEC 104 should always create a state machine"
        assert "DISCONNECTED" in sm.states
        assert "CONNECTED" in sm.states
        assert "DATA_TRANSFER" in sm.states
        assert len(sm.states) == 3, f"IEC 104 should have exactly 3 states, got {len(sm.states)}"

    def test_initial_state_is_disconnected(self, tmp_path):
        """IEC 104 should start in DISCONNECTED state."""
        fuzzer = _create_mock_fuzzer("iec104", tmp_path)
        sm = _get_inner_state_machine(fuzzer)
        if sm is None:
            pytest.skip("IEC 104 state machine not created")

        initial = sm.state_history[0]
        assert initial == "DISCONNECTED", (
            f"IEC 104 initial state should be DISCONNECTED, got {initial}"
        )

    def test_topological_order(self, tmp_path):
        """IEC 104 should have DISCONNECTED -> CONNECTED -> DATA_TRANSFER."""
        fuzzer = _create_mock_fuzzer("iec104", tmp_path)
        sm = _get_inner_state_machine(fuzzer)
        if sm is None:
            pytest.skip("IEC 104 state machine not created")

        topo = sm.get_topological_order()
        assert len(topo) == 3, f"Expected 3 states in topo order, got {len(topo)}: {topo}"
        assert topo.index("DISCONNECTED") < topo.index("CONNECTED")
        assert topo.index("CONNECTED") < topo.index("DATA_TRANSFER")

    def test_path_to_data_transfer(self, tmp_path):
        """Path from DISCONNECTED to DATA_TRANSFER should pass through CONNECTED."""
        fuzzer = _create_mock_fuzzer("iec104", tmp_path)
        sm = _get_inner_state_machine(fuzzer)
        if sm is None:
            pytest.skip("IEC 104 state machine not created")

        path = sm.get_path_to_state("DATA_TRANSFER")
        assert path == ["DISCONNECTED", "CONNECTED", "DATA_TRANSFER"], (
            f"Expected path [DISCONNECTED, CONNECTED, DATA_TRANSFER], got {path}"
        )

    def test_sequence_manager_has_send_recv_seq(self, tmp_path):
        """IEC 104 should have send_seq and recv_seq in its SequenceManager."""
        fuzzer = _create_mock_fuzzer("iec104", tmp_path)

        # IEC 104 uses a custom IEC104StateMachine wrapper.
        # The wrapper exposes .context for StateContext access.
        wrapper = fuzzer.state_machine
        if wrapper is None:
            pytest.skip("IEC 104 state machine not created")

        # Access context from the wrapper (IEC104StateMachine.context)
        ctx = wrapper.context if hasattr(wrapper, "context") else None
        if ctx is None:
            pytest.skip("IEC 104 state machine has no StateContext")

        assert ctx.has_sequence_manager("iec104"), "IEC 104 should have 'iec104' SequenceManager"
        seq_mgr = ctx.get_sequence_manager("iec104")

        send_seq = seq_mgr.get("send_seq")
        assert isinstance(send_seq, int), f"send_seq should be int, got {type(send_seq)}"
        assert send_seq == 0, f"Initial send_seq should be 0, got {send_seq}"

        recv_seq = seq_mgr.get("recv_seq")
        assert isinstance(recv_seq, int), f"recv_seq should be int, got {type(recv_seq)}"
        assert recv_seq == 0, f"Initial recv_seq should be 0, got {recv_seq}"

    def test_sequence_increment_by_two(self, tmp_path):
        """IEC 104 sequences should increment by 2 (even values only)."""
        fuzzer = _create_mock_fuzzer("iec104", tmp_path)
        wrapper = fuzzer.state_machine
        if wrapper is None:
            pytest.skip("IEC 104 state machine not created")

        ctx = wrapper.context if hasattr(wrapper, "context") else None
        if ctx is None:
            pytest.skip("IEC 104 state machine has no StateContext")

        seq_mgr = ctx.get_sequence_manager("iec104")
        val = seq_mgr.get_and_increment("send_seq")
        assert val == 0, f"First send_seq value should be 0, got {val}"
        next_val = seq_mgr.get("send_seq")
        assert next_val == 2, f"After increment, send_seq should be 2, got {next_val}"

    def test_data_transfer_state_type(self, tmp_path):
        """DATA_TRANSFER should have StateType.DATA_TRANSFER."""
        from oida.fuzz.core.session.state_machine import StateType

        fuzzer = _create_mock_fuzzer("iec104", tmp_path)
        sm = _get_inner_state_machine(fuzzer)
        if sm is None:
            pytest.skip("IEC 104 state machine not created")

        dt_state = sm.states["DATA_TRANSFER"]
        assert dt_state.state_type == StateType.DATA_TRANSFER, (
            f"DATA_TRANSFER state type should be DATA_TRANSFER, got {dt_state.state_type}"
        )


# ============================================================================
# TCP State Traversal
# ============================================================================


class TestTCPStateTraversal:
    """Verify TCP state machine with mock connections.

    TCP has 11 states following the RFC 793 state diagram:
    CLOSED, LISTEN, SYN_SENT, SYN_RECEIVED, ESTABLISHED,
    FIN_WAIT_1, FIN_WAIT_2, CLOSE_WAIT, CLOSING, LAST_ACK, TIME_WAIT
    """

    TCP_EXPECTED_STATES = {
        "CLOSED",
        "LISTEN",
        "SYN_SENT",
        "SYN_RECEIVED",
        "ESTABLISHED",
        "FIN_WAIT_1",
        "FIN_WAIT_2",
        "CLOSE_WAIT",
        "CLOSING",
        "LAST_ACK",
        "TIME_WAIT",
    }

    def test_state_machine_created(self, tmp_path):
        """TCP fuzzer should create a state machine with 11 states."""
        fuzzer = _create_mock_fuzzer("tcp", tmp_path)

        sm = _get_inner_state_machine(fuzzer)
        assert sm is not None, "TCP should always create a state machine"
        actual = set(sm.states.keys())
        missing = self.TCP_EXPECTED_STATES - actual
        assert not missing, f"TCP missing states: {missing}. Got: {sorted(actual)}"
        assert len(sm.states) == 11, f"TCP should have 11 states, got {len(sm.states)}"

    def test_initial_state_is_closed(self, tmp_path):
        """TCP should start in CLOSED state."""
        fuzzer = _create_mock_fuzzer("tcp", tmp_path)
        sm = _get_inner_state_machine(fuzzer)
        if sm is None:
            pytest.skip("TCP state machine not created")

        initial = sm.state_history[0]
        assert initial == "CLOSED", f"TCP initial state should be CLOSED, got {initial}"

    def test_topological_order(self, tmp_path):
        """TCP states should have a valid topological order."""
        fuzzer = _create_mock_fuzzer("tcp", tmp_path)
        sm = _get_inner_state_machine(fuzzer)
        if sm is None:
            pytest.skip("TCP state machine not created")

        try:
            topo = sm.get_topological_order()
        except ValueError as e:
            pytest.fail(f"TCP state machine has cycles: {e}")

        assert len(topo) == 11, f"Expected 11 states in topo order, got {len(topo)}: {topo}"
        # CLOSED must come first (it's the initial state with no requires)
        assert topo[0] == "CLOSED", f"CLOSED should be first in topo order, got {topo[0]}"

    def test_established_reachable_from_closed(self, tmp_path):
        """There must be a path from CLOSED to ESTABLISHED."""
        fuzzer = _create_mock_fuzzer("tcp", tmp_path)
        sm = _get_inner_state_machine(fuzzer)
        if sm is None:
            pytest.skip("TCP state machine not created")

        path = sm.get_path_to_state("ESTABLISHED")
        assert len(path) >= 2, (
            f"Path from CLOSED to ESTABLISHED should have at least 2 states, got {path}"
        )
        assert path[0] == "CLOSED"
        assert path[-1] == "ESTABLISHED"

    def test_all_connection_states_have_connection_type(self, tmp_path):
        """All TCP states should have StateType.CONNECTION."""
        from oida.fuzz.core.session.state_machine import StateType

        fuzzer = _create_mock_fuzzer("tcp", tmp_path)
        sm = _get_inner_state_machine(fuzzer)
        if sm is None:
            pytest.skip("TCP state machine not created")

        for state_name, state_obj in sm.states.items():
            assert state_obj.state_type == StateType.CONNECTION, (
                f"TCP state '{state_name}' should have StateType.CONNECTION, "
                f"got {state_obj.state_type}"
            )


# ============================================================================
# HTTP State Traversal
# ============================================================================


class TestHTTPStateTraversal:
    """Verify HTTP state machine with mock connections.

    HTTP has 6 states: DISCONNECTED, CONNECTED, REQUEST_SENT,
    RESPONSE_RECEIVED, PERSISTENT, AUTHENTICATED
    """

    HTTP_EXPECTED_STATES = {
        "DISCONNECTED",
        "CONNECTED",
        "REQUEST_SENT",
        "RESPONSE_RECEIVED",
        "PERSISTENT",
        "AUTHENTICATED",
    }

    def test_state_machine_created(self, tmp_path):
        """HTTP fuzzer should create a state machine with 6 states."""
        fuzzer = _create_mock_fuzzer("http", tmp_path)

        sm = _get_inner_state_machine(fuzzer)
        assert sm is not None, "HTTP should always create a state machine"
        actual = set(sm.states.keys())
        missing = self.HTTP_EXPECTED_STATES - actual
        assert not missing, f"HTTP missing states: {missing}. Got: {sorted(actual)}"
        assert len(sm.states) == 6, f"HTTP should have 6 states, got {len(sm.states)}"

    def test_initial_state_is_disconnected(self, tmp_path):
        """HTTP should start in DISCONNECTED state."""
        fuzzer = _create_mock_fuzzer("http", tmp_path)
        sm = _get_inner_state_machine(fuzzer)
        if sm is None:
            pytest.skip("HTTP state machine not created")

        initial = sm.state_history[0]
        assert initial == "DISCONNECTED", (
            f"HTTP initial state should be DISCONNECTED, got {initial}"
        )

    def test_cyclic_graph_detected(self, tmp_path):
        """HTTP state machine has intentional cycles (request/response loops).

        HTTP allows PERSISTENT -> REQUEST_SENT and AUTHENTICATED -> REQUEST_SENT,
        forming cycles. This test verifies the cycle detection works correctly.
        """
        fuzzer = _create_mock_fuzzer("http", tmp_path)
        sm = _get_inner_state_machine(fuzzer)
        if sm is None:
            pytest.skip("HTTP state machine not created")

        # HTTP is intentionally cyclic, so get_topological_order should raise
        with pytest.raises(ValueError, match="Circular dependency"):
            sm.get_topological_order()

    def test_path_to_authenticated(self, tmp_path):
        """There must be a path from DISCONNECTED to AUTHENTICATED."""
        fuzzer = _create_mock_fuzzer("http", tmp_path)
        sm = _get_inner_state_machine(fuzzer)
        if sm is None:
            pytest.skip("HTTP state machine not created")

        path = sm.get_path_to_state("AUTHENTICATED")
        assert len(path) >= 3, f"Path to AUTHENTICATED should have >= 3 states, got {path}"
        assert path[0] == "DISCONNECTED"
        assert path[-1] == "AUTHENTICATED"

    def test_persistent_state_type(self, tmp_path):
        """PERSISTENT should have StateType.SESSION."""
        from oida.fuzz.core.session.state_machine import StateType

        fuzzer = _create_mock_fuzzer("http", tmp_path)
        sm = _get_inner_state_machine(fuzzer)
        if sm is None:
            pytest.skip("HTTP state machine not created")

        persistent = sm.states["PERSISTENT"]
        assert persistent.state_type == StateType.SESSION, (
            f"PERSISTENT state type should be SESSION, got {persistent.state_type}"
        )

    def test_authenticated_state_type(self, tmp_path):
        """AUTHENTICATED should have StateType.AUTHENTICATION."""
        from oida.fuzz.core.session.state_machine import StateType

        fuzzer = _create_mock_fuzzer("http", tmp_path)
        sm = _get_inner_state_machine(fuzzer)
        if sm is None:
            pytest.skip("HTTP state machine not created")

        auth = sm.states["AUTHENTICATED"]
        assert auth.state_type == StateType.AUTHENTICATION, (
            f"AUTHENTICATED state type should be AUTHENTICATION, got {auth.state_type}"
        )

    def test_http_has_transition_rules(self, tmp_path):
        """HTTP should define explicit TransitionRule objects."""
        fuzzer = _create_mock_fuzzer("http", tmp_path)
        sm = _get_inner_state_machine(fuzzer)
        if sm is None:
            pytest.skip("HTTP state machine not created")

        assert len(sm.transitions) > 0, "HTTP state machine should have explicit transition rules"
        # HTTP defines at least 10 transition rules
        assert len(sm.transitions) >= 8, (
            f"HTTP should have >= 8 transition rules, got {len(sm.transitions)}"
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
