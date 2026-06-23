"""
Deep state machine verification against real Docker mock services.

Unlike test_state_traversal.py which only checks graph structure with
MockConnectionFactory, these tests run fuzzers against actual Docker mock
servers and verify that state machine states are reached, context data is
populated, and sequence numbers increment after fuzz_all() completes.

Requires Docker mocks to be running (``make mock-start``).
Each test class skips automatically if its Docker mock is unavailable.
"""

import pytest

from .conftest import (
    create_fuzzer_config,
    require_docker_mock,
    run_fuzz_capture,
)
from ..conftest import MOCK_HOST, MOCK_PORTS

pytestmark = pytest.mark.integration_fuzzers


# ============================================================================
# Helpers
# ============================================================================


def _get_fuzzer_class(protocol_name):
    """Get fuzzer class for a protocol, skipping if unavailable."""
    pytest.importorskip("boofuzz")
    from oida.fuzz.protocols import PROTOCOL_FUZZERS

    fuzzer_class = PROTOCOL_FUZZERS.get(protocol_name)
    if not fuzzer_class:
        pytest.skip(f"{protocol_name} fuzzer not available")
    return fuzzer_class


def _create_real_fuzzer(protocol_name, port, session_path, **protocol_options):
    """Create fuzzer with real TCP connection (no MockConnectionFactory).

    Returns the fuzzer with its session initialized (triggers _define_state_machine).
    Config-level keys (index_start, index_end) are extracted from protocol_options.
    """
    fuzzer_class = _get_fuzzer_class(protocol_name)

    # Extract config-level overrides from protocol_options
    config_overrides = {}
    for key in ("index_start", "index_end"):
        if key in protocol_options:
            config_overrides[key] = protocol_options.pop(key)

    config = create_fuzzer_config(
        MOCK_HOST,
        port,
        protocol_name,
        session_path,
        index_end=config_overrides.pop("index_end", 5),
        skip_pre_send_checks=True,
        protocol_options=protocol_options,
        **config_overrides,
    )

    try:
        fuzzer = fuzzer_class(config=config)
        # Trigger lazy session initialization (calls _define_state_machine)
        _ = fuzzer.session
        return fuzzer
    except ImportError as e:
        pytest.skip(f"Missing dependency: {e}")


def _get_inner_state_machine(fuzzer):
    """Get framework StateMachine, unwrapping protocol-specific wrappers."""
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
# MMS: CONNECTED → COTP_ESTABLISHED → MMS_ASSOCIATED
# Docker: mms-libiec61850 on port 102
# ============================================================================


@pytest.mark.mms
@pytest.mark.xdist_group("mms_service")
class TestMMSReal:
    """Verify MMS state machine reaches all states against real mms-libiec61850."""

    def _make_fuzzer(self, tmp_path):
        require_docker_mock("mms")
        return _create_real_fuzzer("mms", MOCK_PORTS["mms"], str(tmp_path / "session"))

    def test_mms_reaches_all_states(self, tmp_path):
        """MMS should reach CONNECTED, COTP_ESTABLISHED, MMS_ASSOCIATED."""
        fuzzer = self._make_fuzzer(tmp_path)
        sm = _get_inner_state_machine(fuzzer)
        if sm is None:
            pytest.skip("MMS state machine not created")

        visited = set(sm.get_state_history())
        assert "CONNECTED" in visited
        assert "COTP_ESTABLISHED" in visited
        assert "MMS_ASSOCIATED" in visited

    def test_mms_cotp_flag_set(self, tmp_path):
        """COTP connection flag should be True after handshake."""
        fuzzer = self._make_fuzzer(tmp_path)
        ctx = getattr(fuzzer, "_state_context", None)
        if ctx is None:
            pytest.skip("MMS does not expose _state_context")

        assert ctx.get("cotp_connection_established") is True

    def test_mms_association_flag_set(self, tmp_path):
        """MMS association flag should be True after AARE received."""
        fuzzer = self._make_fuzzer(tmp_path)
        ctx = getattr(fuzzer, "_state_context", None)
        if ctx is None:
            pytest.skip("MMS does not expose _state_context")

        assert ctx.get("association_established") is True

    def test_mms_invoke_id_advanced(self, tmp_path):
        """Invoke ID should advance past initial value during protocol definition.

        MMS builds requests with _next_invoke_id() during _define_protocol(),
        so the sequence counter advances at build time, not during fuzz_all().
        """
        fuzzer = self._make_fuzzer(tmp_path)
        sm = _get_inner_state_machine(fuzzer)
        if sm is None:
            pytest.skip("MMS state machine not created")

        ctx = fuzzer._state_context
        seq_mgr = ctx.get_sequence_manager("mms")
        invoke_id = seq_mgr.get("invoke_id")
        # invoke_id starts at 1 and gets incremented during _define_protocol()
        assert invoke_id > 1, (
            f"invoke_id should advance past initial (1) during protocol definition, got {invoke_id}"
        )

    def test_mms_negotiated_pdu(self, tmp_path):
        """Negotiated max PDU size should be set after handshake."""
        fuzzer = self._make_fuzzer(tmp_path)
        ctx = getattr(fuzzer, "_state_context", None)
        if ctx is None:
            pytest.skip("MMS does not expose _state_context")

        negotiated = ctx.get("negotiated_max_pdu")
        # The libiec61850 server should negotiate a PDU size
        assert negotiated is not None, "negotiated_max_pdu should be set"
        assert isinstance(negotiated, int)
        assert negotiated > 0


# ============================================================================
# ADS: CONNECTED → ADS_VALIDATED
# Docker: ads-mock on port 48898
# ============================================================================


@pytest.mark.ads
@pytest.mark.timeout(120)
class TestADSReal:
    """Verify ADS state machine reaches ADS_VALIDATED against real ads-mock."""

    def _make_fuzzer(self, tmp_path):
        require_docker_mock("ads")
        return _create_real_fuzzer("ads", MOCK_PORTS["ads"], str(tmp_path / "session"))

    def test_ads_reaches_all_states(self, tmp_path):
        """ADS should reach CONNECTED and ADS_VALIDATED."""
        fuzzer = self._make_fuzzer(tmp_path)
        sm = _get_inner_state_machine(fuzzer)
        if sm is None:
            pytest.skip("ADS state machine not created")

        visited = set(sm.get_state_history())
        assert "CONNECTED" in visited
        assert "ADS_VALIDATED" in visited

    def test_ads_device_validated(self, tmp_path):
        """device_validated should be True after READ_DEVICE_INFO."""
        fuzzer = self._make_fuzzer(tmp_path)
        assert fuzzer.device_validated is True

    def test_ads_device_name_extracted(self, tmp_path):
        """Device name should be extracted from READ_DEVICE_INFO response."""
        fuzzer = self._make_fuzzer(tmp_path)
        ctx = getattr(fuzzer, "_state_context", None)
        if ctx is None:
            pytest.skip("ADS does not expose _state_context")

        device_name = ctx.get("device_name")
        assert device_name is not None, "device_name should be set"
        assert len(device_name) > 0, "device_name should be non-empty"

    def test_ads_device_version_extracted(self, tmp_path):
        """Device version should be extracted from READ_DEVICE_INFO response."""
        fuzzer = self._make_fuzzer(tmp_path)
        ctx = getattr(fuzzer, "_state_context", None)
        if ctx is None:
            pytest.skip("ADS does not expose _state_context")

        device_version = ctx.get("device_version")
        assert device_version is not None, "device_version should be set"
        assert "." in device_version, f"device_version should contain '.': {device_version}"

    def test_ads_invoke_id_increments(self, tmp_path):
        """Invoke ID should increment during fuzz_all() via DynamicDWord."""
        fuzzer = self._make_fuzzer(tmp_path)
        sm = _get_inner_state_machine(fuzzer)
        if sm is None:
            pytest.skip("ADS state machine not created")

        ctx = fuzzer._state_context
        seq_mgr = ctx.get_sequence_manager("ads")
        initial_id = seq_mgr.get("invoke_id")

        run_fuzz_capture(fuzzer, timeout_seconds=90)
        final_id = seq_mgr.get("invoke_id")
        # ADS uses DynamicDWord with lambda, so invoke_id increments per request
        assert final_id > initial_id, (
            f"invoke_id should increment during fuzz_all(): {initial_id} → {final_id}"
        )


# ============================================================================
# EtherNet/IP: CONNECTED → SESSION_REGISTERED
# Docker: ethernetip-mock (oida-mock) on port 44818
# ============================================================================


@pytest.mark.ethernetip
class TestEtherNetIPReal:
    """Verify EtherNet/IP state machine reaches SESSION_REGISTERED."""

    def _make_fuzzer(self, tmp_path):
        require_docker_mock("ethernetip")
        return _create_real_fuzzer(
            "ethernetip", MOCK_PORTS["ethernetip"], str(tmp_path / "session")
        )

    def test_enip_reaches_all_states(self, tmp_path):
        """EtherNet/IP should reach CONNECTED and SESSION_REGISTERED."""
        fuzzer = self._make_fuzzer(tmp_path)
        sm = _get_inner_state_machine(fuzzer)
        if sm is None:
            pytest.skip("EtherNet/IP state machine not created")

        visited = set(sm.get_state_history())
        assert "CONNECTED" in visited
        assert "SESSION_REGISTERED" in visited

    def test_enip_session_handle_nonzero(self, tmp_path):
        """Session handle should be non-zero after RegisterSession."""
        fuzzer = self._make_fuzzer(tmp_path)
        assert fuzzer.session_handle != 0, "session_handle should be non-zero"

    def test_enip_session_in_context(self, tmp_path):
        """Session handle in StateContext should match fuzzer attribute."""
        fuzzer = self._make_fuzzer(tmp_path)
        ctx = getattr(fuzzer, "_state_context", None)
        if ctx is None:
            pytest.skip("EtherNet/IP does not expose _state_context")

        ctx_handle = ctx.get("session_handle")
        assert ctx_handle is not None, "session_handle should be in context"
        assert ctx_handle == fuzzer.session_handle

    def test_enip_sender_context_configured(self, tmp_path):
        """Sender context sequence should be configured in SequenceManager."""
        fuzzer = self._make_fuzzer(tmp_path)

        ctx = getattr(fuzzer, "_state_context", None)
        if ctx is None:
            pytest.skip("EtherNet/IP does not expose _state_context")

        assert ctx.has_sequence_manager("enip"), "EtherNet/IP should have 'enip' SequenceManager"
        seq_mgr = ctx.get_sequence_manager("enip")
        val = seq_mgr.get("sender_context")
        assert isinstance(val, int), f"sender_context should be int, got {type(val)}"


# ============================================================================
# OPC UA: CONNECTED → HELLO_COMPLETE → SECURE_CHANNEL → SESSION_ACTIVE
# Docker: opcua-insecure on port 4842 (anonymous, no security)
# ============================================================================


@pytest.mark.opcua
@pytest.mark.timeout(120)
class TestOPCUAReal:
    """Verify OPC UA state machine reaches all 4 states against opcua-insecure."""

    def _make_fuzzer(self, tmp_path):
        require_docker_mock("opcua_insecure")
        return _create_real_fuzzer(
            "opcua",
            MOCK_PORTS["opcua_insecure"],
            str(tmp_path / "session"),
            use_session=True,
        )

    def test_opcua_reaches_all_states(self, tmp_path):
        """OPC UA should reach all 4 states."""
        fuzzer = self._make_fuzzer(tmp_path)
        sm = _get_inner_state_machine(fuzzer)
        if sm is None:
            pytest.skip("OPC UA state machine not created (asyncua handshake failed)")

        visited = set(sm.get_state_history())
        expected = {"CONNECTED", "HELLO_COMPLETE", "SECURE_CHANNEL", "SESSION_ACTIVE"}
        missing = expected - visited
        assert not missing, f"OPC UA missing states: {missing}. Visited: {visited}"

    def test_opcua_channel_id_set(self, tmp_path):
        """Secure channel ID should be non-zero after handshake."""
        fuzzer = self._make_fuzzer(tmp_path)
        sm = _get_inner_state_machine(fuzzer)
        if sm is None:
            pytest.skip("OPC UA state machine not created")

        assert fuzzer.secure_channel_id != 0, "secure_channel_id should be non-zero"

    def test_opcua_token_id_set(self, tmp_path):
        """Token ID should be non-zero after handshake."""
        fuzzer = self._make_fuzzer(tmp_path)
        sm = _get_inner_state_machine(fuzzer)
        if sm is None:
            pytest.skip("OPC UA state machine not created")

        assert fuzzer.token_id != 0, "token_id should be non-zero"

    def test_opcua_auth_token_set(self, tmp_path):
        """Auth token should be set in context after session creation."""
        fuzzer = self._make_fuzzer(tmp_path)
        ctx = getattr(fuzzer, "_state_context", None)
        if ctx is None:
            pytest.skip("OPC UA does not expose _state_context")

        sm = _get_inner_state_machine(fuzzer)
        if sm is None:
            pytest.skip("OPC UA state machine not created")

        auth_token = ctx.get("auth_token")
        assert auth_token is not None, "auth_token should be set in context"

    def test_opcua_server_nonce_stored(self, tmp_path):
        """Server nonce should be stored in CryptoStateManager."""
        fuzzer = self._make_fuzzer(tmp_path)
        ctx = getattr(fuzzer, "_state_context", None)
        if ctx is None:
            pytest.skip("OPC UA does not expose _state_context")

        sm = _get_inner_state_machine(fuzzer)
        if sm is None:
            pytest.skip("OPC UA state machine not created")

        nonce = ctx.crypto.get_nonce("server_nonce")
        assert nonce is not None, "server_nonce should be stored in CryptoStateManager"

    def test_opcua_sequence_numbers_increment(self, tmp_path):
        """Sequence number and request ID should increment after fuzz_all()."""
        fuzzer = self._make_fuzzer(tmp_path)
        sm = _get_inner_state_machine(fuzzer)
        if sm is None:
            pytest.skip("OPC UA state machine not created")

        ctx = fuzzer._state_context
        seq_mgr = ctx.get_sequence_manager("opcua")
        initial_seq = seq_mgr.get("sequence_number")
        initial_req = seq_mgr.get("request_id")

        run_fuzz_capture(fuzzer, timeout_seconds=60)
        final_seq = seq_mgr.get("sequence_number")
        final_req = seq_mgr.get("request_id")
        assert final_seq > initial_seq, (
            f"sequence_number should increment: {initial_seq} → {final_seq}"
        )
        assert final_req > initial_req, f"request_id should increment: {initial_req} → {final_req}"


# ============================================================================
# IEC 104: DISCONNECTED → CONNECTED → DATA_TRANSFER
# Docker: iec104-lib60870 on port 2404
# ============================================================================


@pytest.mark.iec104
@pytest.mark.timeout(120)
@pytest.mark.xdist_group("iec104_service")
class TestIEC104Real:
    """Verify IEC 104 state machine and sequence configuration.

    Note: IEC 104 state transitions (DISCONNECTED→CONNECTED→DATA_TRANSFER) are NOT
    triggered automatically during fuzz_all(). The STARTDT handshake is handled by
    IEC104SocketConnection at the TCP layer, but the IEC104StateMachine wrapper
    is not called back. These tests verify the state machine is created, configured
    with correct sequences, and accessible — not that transitions occur.
    """

    def _make_fuzzer(self, tmp_path):
        require_docker_mock("iec104")
        return _create_real_fuzzer("iec104", MOCK_PORTS["iec104"], str(tmp_path / "session"))

    def test_iec104_state_machine_created(self, tmp_path):
        """IEC 104 state machine should be created with 3 states."""
        fuzzer = self._make_fuzzer(tmp_path)
        sm = _get_inner_state_machine(fuzzer)
        assert sm is not None, "IEC 104 state machine should be created"
        assert len(sm.states) == 3, f"Expected 3 states, got {len(sm.states)}"
        state_names = {s.name for s in sm.states.values()}
        assert state_names == {"DISCONNECTED", "CONNECTED", "DATA_TRANSFER"}

    def test_iec104_initial_state_disconnected(self):
        """A freshly-constructed IEC 104 state machine starts in DISCONNECTED.

        The fully-initialized *fuzzer's* machine is intentionally advanced to
        DATA_TRANSFER so it can fuzz I-format frames (which are only valid in
        data-transfer state), so the initial-state contract is asserted on a bare
        state machine rather than on the ready-to-fuzz fuzzer.
        """
        from oida.fuzz.protocols.iec104 import IEC104StateMachine

        sm = IEC104StateMachine()
        assert sm.current_state.name == "DISCONNECTED"

    def test_iec104_sequences_configured(self, tmp_path):
        """send_seq and recv_seq should be configured in SequenceManager."""
        fuzzer = self._make_fuzzer(tmp_path)
        wrapper = fuzzer.state_machine
        if wrapper is None:
            pytest.skip("IEC 104 state machine not created")

        ctx = wrapper.context if hasattr(wrapper, "context") else None
        if ctx is None:
            pytest.skip("IEC 104 state machine has no StateContext")

        seq_mgr = ctx.get_sequence_manager("iec104")
        send_seq = seq_mgr.get("send_seq")
        recv_seq = seq_mgr.get("recv_seq")
        assert isinstance(send_seq, int), f"send_seq should be int, got {type(send_seq)}"
        assert isinstance(recv_seq, int), f"recv_seq should be int, got {type(recv_seq)}"
        assert send_seq == 0, f"send_seq should start at 0, got {send_seq}"
        assert recv_seq == 0, f"recv_seq should start at 0, got {recv_seq}"

    def test_iec104_data_transfer_path_exists(self, tmp_path):
        """State machine should have a path from DISCONNECTED to DATA_TRANSFER."""
        fuzzer = self._make_fuzzer(tmp_path)
        sm = _get_inner_state_machine(fuzzer)
        if sm is None:
            pytest.skip("IEC 104 state machine not created")

        # DATA_TRANSFER requires CONNECTED, which requires DISCONNECTED
        dt_state = sm.states.get("DATA_TRANSFER")
        assert dt_state is not None, "DATA_TRANSFER state should exist"
        assert "CONNECTED" in dt_state.requires, (
            f"DATA_TRANSFER should require CONNECTED, got {dt_state.requires}"
        )


# ============================================================================
# MQTT: DISCONNECTED → CONNECTED → CONNECT_SENT → CONNACK_RECEIVED → READY
# Docker: mqtt-auth on port 1884 (admin:admin)
# ============================================================================


@pytest.mark.mqtt
@pytest.mark.timeout(120)
class TestMQTTReal:
    """Verify MQTT state machine reaches READY against mqtt-auth broker."""

    def _make_fuzzer(self, tmp_path):
        require_docker_mock("mqtt_auth")
        return _create_real_fuzzer(
            "mqtt",
            MOCK_PORTS["mqtt_auth"],
            str(tmp_path / "session"),
            use_auth=True,
            mqtt_username="admin",
            mqtt_password="admin",
        )

    def test_mqtt_reaches_ready_state(self, tmp_path):
        """MQTT should reach READY state after fuzz_all()."""
        fuzzer = self._make_fuzzer(tmp_path)
        sm = _get_inner_state_machine(fuzzer)
        if sm is None:
            pytest.skip("MQTT state machine not created (mock detection or auth issue)")

        run_fuzz_capture(fuzzer, timeout_seconds=60)
        visited = set(sm.get_state_history())
        assert "READY" in visited, (
            f"READY should be in history after fuzz_all(). Visited: {visited}"
        )

    def test_mqtt_all_states_visited(self, tmp_path):
        """All 5 MQTT states should be visited after fuzz_all()."""
        fuzzer = self._make_fuzzer(tmp_path)
        sm = _get_inner_state_machine(fuzzer)
        if sm is None:
            pytest.skip("MQTT state machine not created")

        run_fuzz_capture(fuzzer, timeout_seconds=60)
        visited = set(sm.get_state_history())
        expected = {"DISCONNECTED", "CONNECTED", "CONNECT_SENT", "CONNACK_RECEIVED", "READY"}
        missing = expected - visited
        assert not missing, f"MQTT missing states: {missing}. Visited: {visited}"

    def test_mqtt_connack_stored(self, tmp_path):
        """CONNACK response should be stored in StateContext after auth."""
        fuzzer = self._make_fuzzer(tmp_path)
        sm = _get_inner_state_machine(fuzzer)
        if sm is None:
            pytest.skip("MQTT state machine not created")

        run_fuzz_capture(fuzzer, timeout_seconds=60)
        ctx = fuzzer._state_context
        connack = ctx.get_response("CONNACK")
        assert connack is not None, "CONNACK response should be stored in context"

    def test_mqtt_packet_id_increments(self, tmp_path):
        """Packet ID (DynamicWord) increments when a packet-id-bearing request is fuzzed.

        Fuzz the PUBLISH request directly rather than via fuzz_all(): the early
        malformed/length requests make the broker RST the connection, which trips
        boofuzz's per-request crash-threshold long before fuzz_all() reaches the
        late PUBLISH/SUBSCRIBE phases — so full traversal never renders a
        packet_id field. Targeting PUBLISH deterministically exercises the
        DynamicWord('packet_id') -> _next_packet_id() mechanism.
        """
        import threading

        fuzzer = self._make_fuzzer(tmp_path)
        sm = _get_inner_state_machine(fuzzer)
        if sm is None:
            pytest.skip("MQTT state machine not created")

        ctx = fuzzer._state_context
        seq_mgr = ctx.get_sequence_manager("mqtt")
        initial_id = seq_mgr.get("packet_id")

        t = threading.Thread(target=lambda: fuzzer.fuzz_node("mqtt_publish"), daemon=True)
        t.start()
        t.join(timeout=60)

        final_id = seq_mgr.get("packet_id")
        assert final_id > initial_id, (
            f"packet_id should increment when fuzzing PUBLISH: {initial_id} → {final_id}"
        )

    def test_mqtt_transition_log_has_timestamps(self, tmp_path):
        """Each transition log entry should have a timestamp."""
        fuzzer = self._make_fuzzer(tmp_path)
        sm = _get_inner_state_machine(fuzzer)
        if sm is None:
            pytest.skip("MQTT state machine not created")

        run_fuzz_capture(fuzzer, timeout_seconds=60)
        log = sm.get_transition_log()
        if len(log) == 0:
            pytest.skip("No transitions recorded")

        for entry in log:
            assert "timestamp" in entry, f"Transition entry missing timestamp: {entry}"


# ============================================================================
# TCP (structural only): 11-state RFC 793 state machine
# Docker: modbus port 502 as a TCP endpoint
# ============================================================================


@pytest.mark.modbus
class TestTCPStructural:
    """Verify TCP state machine structure (no real traversal)."""

    def _make_fuzzer(self, tmp_path):
        require_docker_mock("modbus")
        return _create_real_fuzzer("tcp", MOCK_PORTS["modbus"], str(tmp_path / "session"))

    def test_tcp_state_machine_created(self, tmp_path):
        """TCP fuzzer should create a state machine with 11 states."""
        fuzzer = self._make_fuzzer(tmp_path)
        sm = _get_inner_state_machine(fuzzer)
        assert sm is not None, "TCP should always create a state machine"
        assert len(sm.states) == 11, f"TCP should have 11 states, got {len(sm.states)}"

    def test_tcp_closed_to_established_path(self, tmp_path):
        """Path from CLOSED to ESTABLISHED should exist."""
        fuzzer = self._make_fuzzer(tmp_path)
        sm = _get_inner_state_machine(fuzzer)
        if sm is None:
            pytest.skip("TCP state machine not created")

        path = sm.get_path_to_state("ESTABLISHED")
        assert path[0] == "CLOSED"
        assert path[-1] == "ESTABLISHED"

    def test_tcp_full_close_path(self, tmp_path):
        """FIN_WAIT_1, FIN_WAIT_2, TIME_WAIT, and CLOSED should be in graph."""
        fuzzer = self._make_fuzzer(tmp_path)
        sm = _get_inner_state_machine(fuzzer)
        if sm is None:
            pytest.skip("TCP state machine not created")

        graph = sm.get_transition_graph()
        # FIN_WAIT_1 should have edges (part of close sequence)
        assert "FIN_WAIT_1" in graph, "FIN_WAIT_1 should be in transition graph"
        assert "TIME_WAIT" in sm.states, "TIME_WAIT should be a valid state"

    def test_tcp_timeouts_configured(self, tmp_path):
        """TCP states should have appropriate timeouts."""
        fuzzer = self._make_fuzzer(tmp_path)
        sm = _get_inner_state_machine(fuzzer)
        if sm is None:
            pytest.skip("TCP state machine not created")

        syn_sent = sm.states.get("SYN_SENT")
        if syn_sent and syn_sent.timeout:
            assert syn_sent.timeout == 3.0, f"SYN_SENT timeout should be 3s, got {syn_sent.timeout}"


# ============================================================================
# VNC: CONNECTED → VERSION_EXCHANGED → SECURITY_NEGOTIATED → AUTHENTICATED
# Docker: vnc-mock on port 5900 (x11vnc, no auth/security type NONE)
# ============================================================================


@pytest.mark.vnc
@pytest.mark.timeout(120)
class TestVNCReal:
    """Verify VNC state machine reaches AUTHENTICATED against vnc-mock.

    VNC auth is deferred — transitions happen during fuzz_all() via
    _ensure_authenticated(), not during __init__.
    """

    def _make_fuzzer(self, tmp_path):
        require_docker_mock("vnc")
        return _create_real_fuzzer(
            "vnc",
            MOCK_PORTS["vnc"],
            str(tmp_path / "session"),
            use_auth=True,
            vnc_password="password",
        )

    def test_vnc_state_machine_created(self, tmp_path):
        """VNC fuzzer should create a state machine with 4 states."""
        fuzzer = self._make_fuzzer(tmp_path)
        sm = _get_inner_state_machine(fuzzer)
        assert sm is not None, "VNC state machine should be created"
        assert len(sm.states) == 4, f"Expected 4 states, got {len(sm.states)}"

    def test_vnc_reaches_authenticated(self, tmp_path):
        """VNC should reach AUTHENTICATED after fuzz_all() triggers auth."""
        fuzzer = self._make_fuzzer(tmp_path)
        sm = _get_inner_state_machine(fuzzer)
        if sm is None:
            pytest.skip("VNC state machine not created")

        run_fuzz_capture(fuzzer, timeout_seconds=90)
        visited = set(sm.get_state_history())
        assert "AUTHENTICATED" in visited, (
            f"AUTHENTICATED should be in history after fuzz_all(). Visited: {visited}"
        )

    def test_vnc_all_states_visited(self, tmp_path):
        """All 4 VNC states should be visited after fuzz_all()."""
        fuzzer = self._make_fuzzer(tmp_path)
        sm = _get_inner_state_machine(fuzzer)
        if sm is None:
            pytest.skip("VNC state machine not created")

        run_fuzz_capture(fuzzer, timeout_seconds=90)
        visited = set(sm.get_state_history())
        expected = {"CONNECTED", "VERSION_EXCHANGED", "SECURITY_NEGOTIATED", "AUTHENTICATED"}
        missing = expected - visited
        assert not missing, f"VNC missing states: {missing}. Visited: {visited}"

    def test_vnc_security_type_set(self, tmp_path):
        """Fuzzer should have security_type set after auth."""
        fuzzer = self._make_fuzzer(tmp_path)
        sm = _get_inner_state_machine(fuzzer)
        if sm is None:
            pytest.skip("VNC state machine not created")

        run_fuzz_capture(fuzzer, timeout_seconds=90)
        # After auth, fuzzer.security_type should be set (e.g. "NONE" or "VNC_AUTH")
        sec_type = getattr(fuzzer, "security_type", None)
        assert sec_type is not None, "security_type should be set on fuzzer after auth"


# ============================================================================
# FTP: CONNECTED → AUTHENTICATED
# Docker: ftp-mock on port 2121 (vsftpd, user ftpuser:password)
# ============================================================================


@pytest.mark.ftp
@pytest.mark.timeout(120)
class TestFTPReal:
    """Verify FTP state machine reaches AUTHENTICATED against ftp-mock.

    FTP non-TLS auth is deferred — transitions happen during fuzz_all()
    via the StatefulFuzzer authenticator callback.
    """

    def _make_fuzzer(self, tmp_path, need_auth_nodes=False):
        require_docker_mock("ftp")
        extra = {}
        if need_auth_nodes:
            # FTP's first nodes are PRE_AUTH (USER, PASS ~978 mutations).
            # StatefulFuzzer only authenticates when an AUTHENTICATED-state
            # request is reached, so skip past PRE_AUTH nodes.
            extra["index_start"] = 1000
            extra["index_end"] = 1005

        return _create_real_fuzzer(
            "ftp",
            MOCK_PORTS["ftp"],
            str(tmp_path / "session"),
            use_auth=True,
            ftp_username="ftpuser",
            ftp_password="password",
            **extra,
        )

    def test_ftp_state_machine_created(self, tmp_path):
        """FTP fuzzer should create a state machine with 2 states."""
        fuzzer = self._make_fuzzer(tmp_path)
        sm = _get_inner_state_machine(fuzzer)
        assert sm is not None, "FTP state machine should be created"
        state_names = {s.name for s in sm.states.values()}
        assert "CONNECTED" in state_names
        assert "AUTHENTICATED" in state_names

    def test_ftp_reaches_authenticated(self, tmp_path):
        """FTP should reach AUTHENTICATED after fuzz_all() triggers login."""
        fuzzer = self._make_fuzzer(tmp_path, need_auth_nodes=True)
        sm = _get_inner_state_machine(fuzzer)
        if sm is None:
            pytest.skip("FTP state machine not created")

        run_fuzz_capture(fuzzer, timeout_seconds=90)
        visited = set(sm.get_state_history())
        assert "AUTHENTICATED" in visited, (
            f"AUTHENTICATED should be in history after fuzz_all(). Visited: {visited}"
        )

    def test_ftp_transition_log_has_entries(self, tmp_path):
        """Transition log should have entries after fuzz_all()."""
        fuzzer = self._make_fuzzer(tmp_path, need_auth_nodes=True)
        sm = _get_inner_state_machine(fuzzer)
        if sm is None:
            pytest.skip("FTP state machine not created")

        result = run_fuzz_capture(fuzzer, timeout_seconds=90)
        if result.get("exception") and isinstance(result["exception"], ConnectionError):
            pytest.skip(f"FTP mock connection failed (mock may be starting up): {result['exception']}")
        log = sm.get_transition_log()
        assert len(log) > 0, "Transition log should have entries after fuzz_all()"


# ============================================================================
# SMTP: CONNECTED → AUTHENTICATED
# Docker: smtp-mock on port 2530 (Postfix, AUTH LOGIN testuser:password)
# ============================================================================


@pytest.mark.smtp
@pytest.mark.timeout(120)
class TestSMTPReal:
    """Verify SMTP state machine reaches AUTHENTICATED against smtp-mock.

    SMTP auth is deferred — transitions happen during fuzz_all() when the
    connection is open, not during __init__.
    """

    def _make_fuzzer(self, tmp_path):
        require_docker_mock("smtp")
        return _create_real_fuzzer(
            "smtp",
            MOCK_PORTS["smtp"],
            str(tmp_path / "session"),
            use_auth=True,
            smtp_username="testuser",
            smtp_password="password",
        )

    def test_smtp_state_machine_created(self, tmp_path):
        """SMTP fuzzer should create a state machine."""
        fuzzer = self._make_fuzzer(tmp_path)
        sm = _get_inner_state_machine(fuzzer)
        assert sm is not None, "SMTP state machine should be created"

    def test_smtp_reaches_authenticated(self, tmp_path):
        """SMTP should reach AUTHENTICATED after fuzz_all() triggers auth."""
        fuzzer = self._make_fuzzer(tmp_path)
        sm = _get_inner_state_machine(fuzzer)
        if sm is None:
            pytest.skip("SMTP state machine not created")

        run_fuzz_capture(fuzzer, timeout_seconds=90)
        visited = set(sm.get_state_history())
        assert "AUTHENTICATED" in visited, (
            f"AUTHENTICATED should be in history after fuzz_all(). Visited: {visited}"
        )

    def test_smtp_transition_log_has_entries(self, tmp_path):
        """Transition log should have entries after fuzz_all()."""
        fuzzer = self._make_fuzzer(tmp_path)
        sm = _get_inner_state_machine(fuzzer)
        if sm is None:
            pytest.skip("SMTP state machine not created")

        run_fuzz_capture(fuzzer, timeout_seconds=90)
        log = sm.get_transition_log()
        assert len(log) > 0, "Transition log should have entries after fuzz_all()"


# ============================================================================
# HTTP (structural): 6-state cyclic machine
# Docker: http-mock (nginx) on port 8083
# ============================================================================


@pytest.mark.http
class TestHTTPReal:
    """Verify HTTP state machine structure against real http-mock.

    HTTP state machine is structural (cyclic) — no real transitions during
    fuzz. Tests verify the graph structure, not runtime state traversal.
    """

    def _make_fuzzer(self, tmp_path):
        require_docker_mock("http_mock")
        return _create_real_fuzzer("http", MOCK_PORTS["http_mock"], str(tmp_path / "session"))

    def test_http_state_machine_created(self, tmp_path):
        """HTTP fuzzer should create a state machine with 6 states."""
        fuzzer = self._make_fuzzer(tmp_path)
        sm = _get_inner_state_machine(fuzzer)
        assert sm is not None, "HTTP should always create a state machine"
        assert len(sm.states) == 6, f"HTTP should have 6 states, got {len(sm.states)}"

    def test_http_request_response_path(self, tmp_path):
        """Path from DISCONNECTED to RESPONSE_RECEIVED should exist."""
        fuzzer = self._make_fuzzer(tmp_path)
        sm = _get_inner_state_machine(fuzzer)
        if sm is None:
            pytest.skip("HTTP state machine not created")

        path = sm.get_path_to_state("RESPONSE_RECEIVED")
        assert path[0] == "DISCONNECTED"
        assert path[-1] == "RESPONSE_RECEIVED"

    def test_http_persistent_cycle(self, tmp_path):
        """PERSISTENT -> REQUEST_SENT should be a valid transition."""
        fuzzer = self._make_fuzzer(tmp_path)
        sm = _get_inner_state_machine(fuzzer)
        if sm is None:
            pytest.skip("HTTP state machine not created")

        graph = sm.get_transition_graph()
        persistent_targets = graph.get("PERSISTENT", [])
        assert "REQUEST_SENT" in persistent_targets, (
            f"PERSISTENT should transition to REQUEST_SENT, got {persistent_targets}"
        )

    def test_http_has_timeout(self, tmp_path):
        """REQUEST_SENT should have a timeout configured."""
        fuzzer = self._make_fuzzer(tmp_path)
        sm = _get_inner_state_machine(fuzzer)
        if sm is None:
            pytest.skip("HTTP state machine not created")

        request_sent = sm.states.get("REQUEST_SENT")
        if request_sent and request_sent.timeout:
            assert request_sent.timeout == 30.0, (
                f"REQUEST_SENT timeout should be 30s, got {request_sent.timeout}"
            )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
