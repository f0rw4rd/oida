"""
Tests for replay correctness in complex stateful scenarios.

Verifies that the replay mechanism handles real-world complexity including:
- Multi-step protocol sequences (handshake -> auth -> command)
- State machine transitions during replay (reset, re-traverse)
- Crypto state restoration during replay (nonces, tokens, keys)
- Database-backed replay with session state (rolling buffer, crash context)
- Sequence number tracking and restoration across replay
- Edge cases: interrupted sessions, partial sequences, state rollback
- StateContext propagation across replay iterations
"""

import binascii
import os
import tempfile
import time
from datetime import datetime, timedelta

import pytest


def _setup_logging_context():
    """Set up logging context needed by ORM operations."""
    from oida.utils.ics_logger import set_context

    try:
        set_context("TEST", "localhost", 0)
    except Exception:
        pass


# =============================================================================
# Helpers
# =============================================================================


def _make_state_context():
    """Create a StateContext with full state for testing."""
    from oida.fuzz.core.session.state_context import StateContext, ResponseData

    ctx = StateContext()
    ctx.set("channel_id", 42)
    ctx.set("authenticated", True)
    ctx.set_response(
        "HELLO",
        ResponseData(
            raw=b"\x01\x02\x03",
            parsed={"version": "1.0", "features": ["tls", "auth"]},
            response_code=200,
        ),
    )
    ctx.set_response(
        "AUTH",
        ResponseData(
            raw=b"\x04\x05",
            parsed={"token": "abc123", "session_id": 99},
            response_code=200,
        ),
    )
    return ctx


def _make_multi_step_state_machine():
    """Create a multi-step state machine modeling a real protocol handshake.

    States: DISCONNECTED -> CONNECTED -> TLS_ESTABLISHED -> AUTHENTICATED -> READY
    """
    from oida.fuzz.core.session.state_machine import (
        ProtocolState,
        StateMachine,
        StateType,
    )

    disconnected = ProtocolState(
        name="DISCONNECTED",
        state_type=StateType.CONNECTION,
        description="Not connected",
    )
    connected = ProtocolState(
        name="CONNECTED",
        state_type=StateType.CONNECTION,
        requires=["DISCONNECTED"],
        description="TCP connected",
    )
    tls_established = ProtocolState(
        name="TLS_ESTABLISHED",
        state_type=StateType.SESSION,
        requires=["CONNECTED"],
        description="TLS handshake complete",
    )
    authenticated = ProtocolState(
        name="AUTHENTICATED",
        state_type=StateType.AUTHENTICATION,
        requires=["TLS_ESTABLISHED"],
        description="Credentials verified",
    )
    ready = ProtocolState(
        name="READY",
        state_type=StateType.TRANSACTION,
        requires=["AUTHENTICATED"],
        description="Ready for commands",
    )

    return StateMachine(
        initial_state=disconnected,
        states=[disconnected, connected, tls_established, authenticated, ready],
    )


def _make_crypto_state_with_session_data():
    """Create a CryptoStateManager populated with realistic session crypto data."""
    from oida.fuzz.core.session.crypto_state import (
        CryptoStateManager,
        TokenState,
        NonceStrategy,
    )

    crypto = CryptoStateManager("test_session")

    # Generate client nonce
    crypto.generate_nonce("client_nonce", length=32, strategy=NonceStrategy.RANDOM)
    # Store server nonce (received from server)
    crypto.set_nonce("server_nonce", b"\xaa\xbb\xcc\xdd" * 8)

    # Store security token with expiry
    crypto.set_token(
        "security_token",
        TokenState(
            name="security_token",
            value=b"\x01\x02\x03\x04",
            expires_at=datetime.now() + timedelta(hours=1),
        ),
    )

    # Store encryption key
    crypto.set_key("session_key", b"\x00" * 32, algorithm="AES-256-CBC")

    return crypto


def _make_sequence_manager_with_state():
    """Create a SequenceManager advanced past initial values."""
    from oida.fuzz.core.session.sequence import (
        SequenceManager,
        SequenceConfig,
        SequenceDirection,
    )

    mgr = SequenceManager("iec104")
    mgr.add_sequence(
        SequenceConfig(
            name="send_seq",
            initial=0,
            max_value=0x7FFF,
            increment=2,
            direction=SequenceDirection.SEND,
        )
    )
    mgr.add_sequence(
        SequenceConfig(
            name="recv_seq",
            initial=0,
            max_value=0x7FFF,
            increment=2,
            direction=SequenceDirection.RECEIVE,
        )
    )

    # Advance sequences as if we've exchanged several messages
    for _ in range(10):
        mgr.get_and_increment("send_seq")
    for _ in range(8):
        mgr.get_and_increment("recv_seq")

    return mgr


# =============================================================================
# Test Multi-Step Protocol Sequence Replay
# =============================================================================


class TestMultiStepSequenceReplay:
    """Verify replay through multi-step protocol sequences."""

    def test_state_machine_full_traversal_and_reset(self):
        """State machine can traverse full handshake path and reset for replay."""
        sm = _make_multi_step_state_machine()

        # Traverse full handshake path
        sm.transition_to("CONNECTED")
        sm.transition_to("TLS_ESTABLISHED")
        sm.transition_to("AUTHENTICATED")
        sm.transition_to("READY")
        assert sm.get_current_state_name() == "READY"

        # Record history
        first_history = sm.get_state_history()
        assert first_history == [
            "DISCONNECTED",
            "CONNECTED",
            "TLS_ESTABLISHED",
            "AUTHENTICATED",
            "READY",
        ]

        # Reset for replay
        sm.reset()
        assert sm.get_current_state_name() == "DISCONNECTED"
        assert sm.get_state_history() == ["DISCONNECTED"]
        assert sm.get_transition_log() == []

        # Re-traverse (simulating replay)
        sm.transition_to("CONNECTED")
        sm.transition_to("TLS_ESTABLISHED")
        sm.transition_to("AUTHENTICATED")
        sm.transition_to("READY")

        # Same end state
        second_history = sm.get_state_history()
        assert second_history == first_history

    def test_state_machine_reset_preserves_states_and_rules(self):
        """Reset clears history but preserves state definitions and transitions."""
        sm = _make_multi_step_state_machine()

        # Get initial state count
        state_count = len(sm.states)

        # Traverse and reset
        sm.transition_to("CONNECTED")
        sm.transition_to("TLS_ESTABLISHED")
        sm.reset()

        # States and rules are preserved
        assert len(sm.states) == state_count
        assert "TLS_ESTABLISHED" in sm.states
        assert "AUTHENTICATED" in sm.states

        # Can still traverse
        sm.transition_to("CONNECTED")
        assert sm.get_current_state_name() == "CONNECTED"

    def test_traverse_to_state_finds_path_for_replay(self):
        """traverse_to_state correctly rebuilds path to target state."""
        sm = _make_multi_step_state_machine()

        # Jump directly to READY (should traverse through all intermediate states)
        sm.traverse_to_state("READY")
        assert sm.get_current_state_name() == "READY"

        expected_path = [
            "DISCONNECTED",
            "CONNECTED",
            "TLS_ESTABLISHED",
            "AUTHENTICATED",
            "READY",
        ]
        assert sm.get_state_history() == expected_path

    def test_get_path_to_state_deterministic(self):
        """Path computation is deterministic across calls (important for replay)."""
        sm = _make_multi_step_state_machine()

        path1 = sm.get_path_to_state("READY")
        path2 = sm.get_path_to_state("READY")
        assert path1 == path2

    def test_multiple_replay_iterations_are_identical(self):
        """Multiple replay iterations produce identical state traversal."""
        histories = []
        transition_logs = []

        for _ in range(3):
            sm = _make_multi_step_state_machine()
            sm.traverse_to_state("READY")
            histories.append(sm.get_state_history())
            transition_logs.append([(t["from"], t["to"]) for t in sm.get_transition_log()])

        assert all(h == histories[0] for h in histories)
        assert all(t == transition_logs[0] for t in transition_logs)


# =============================================================================
# Test State Machine Transitions with Context During Replay
# =============================================================================


class TestStateMachineContextReplay:
    """Verify StateContext is correctly propagated during replay transitions."""

    def test_context_data_survives_full_traversal(self):
        """Data set in context during traversal is available in final state."""
        from oida.fuzz.core.session.state_context import StateContext
        from oida.fuzz.core.session.state_machine import (
            ProtocolState,
            StateMachine,
            StateType,
        )

        ctx = StateContext()

        def on_connect(context):
            context.set("connected_at", "2024-01-01T00:00:00")
            return True

        def on_auth(context):
            context.set("auth_token", "tok_replay_123")
            context.set("session_id", 42)
            return True

        connected = ProtocolState(
            name="CONNECTED",
            state_type=StateType.CONNECTION,
            setup=on_connect,
        )
        authenticated = ProtocolState(
            name="AUTHENTICATED",
            state_type=StateType.AUTHENTICATION,
            setup=on_auth,
            requires=["CONNECTED"],
        )

        sm = StateMachine(
            initial_state=ProtocolState(name="DISCONNECTED"),
            states=[
                ProtocolState(name="DISCONNECTED"),
                connected,
                authenticated,
            ],
            context=ctx,
        )

        sm.transition_to("CONNECTED")
        sm.transition_to("AUTHENTICATED")

        # Context should have data from all transitions
        assert ctx.get("connected_at") == "2024-01-01T00:00:00"
        assert ctx.get("auth_token") == "tok_replay_123"
        assert ctx.get("session_id") == 42

    def test_context_reset_for_replay_iteration(self):
        """Context can be cleared between replay iterations while preserving config."""
        from oida.fuzz.core.session.state_context import StateContext

        ctx = StateContext()
        ctx.set("config_protocol", "opcua")
        ctx.set("session_id", 42)
        ctx.set("nonce", b"\x01\x02\x03")

        # Clear session-specific data, preserve config
        ctx.clear(preserve_keys=["config_protocol"])

        assert ctx.get("config_protocol") == "opcua"
        assert ctx.get("session_id") is None
        assert ctx.get("nonce") is None

    def test_child_context_for_nested_replay(self):
        """Child context provides isolation for nested replay sequences."""
        from oida.fuzz.core.session.state_context import StateContext, ResponseData

        parent = StateContext()
        parent.set("global_channel_id", 1)
        parent.set_response(
            "HELLO",
            ResponseData(raw=b"\x01", parsed={"version": "1.0"}),
        )

        # Replay iteration 1 - child context
        child1 = parent.create_child()
        child1.set("iteration", 1)
        child1.set("test_payload", b"\xaa\xbb")

        # Replay iteration 2 - fresh child context
        child2 = parent.create_child()
        child2.set("iteration", 2)
        child2.set("test_payload", b"\xcc\xdd")

        # Children inherit from parent
        assert child1.get("global_channel_id") == 1
        assert child2.get("global_channel_id") == 1

        # Children have their own iteration data
        assert child1.get("iteration") == 1
        assert child2.get("iteration") == 2

        # Parent is unaffected
        assert parent.get("iteration") is None

        # Both children can access parent response
        assert child1.get_response("HELLO").parsed["version"] == "1.0"
        assert child2.get_response("HELLO").parsed["version"] == "1.0"

    def test_context_callbacks_fire_during_replay_transitions(self):
        """Context callbacks fire during state transition replay."""
        from oida.fuzz.core.session.state_context import StateContext
        from oida.fuzz.core.session.state_machine import (
            ProtocolState,
            StateMachine,
        )

        ctx = StateContext()
        events = []
        ctx.on_change("set", lambda evt, key, val: events.append((key, val)))

        def setup_connected(context):
            context.set("state", "connected")
            return True

        def setup_auth(context):
            context.set("state", "authenticated")
            return True

        sm = StateMachine(
            initial_state=ProtocolState(name="IDLE"),
            states=[
                ProtocolState(name="IDLE"),
                ProtocolState(name="CONNECTED", setup=setup_connected),
                ProtocolState(name="AUTHENTICATED", setup=setup_auth, requires=["CONNECTED"]),
            ],
            context=ctx,
        )

        sm.transition_to("CONNECTED")
        sm.transition_to("AUTHENTICATED")

        # Callbacks should have recorded both transitions
        assert ("state", "connected") in events
        assert ("state", "authenticated") in events


# =============================================================================
# Test Crypto State Restoration During Replay
# =============================================================================


class TestCryptoStateReplay:
    """Verify crypto state can be restored for deterministic replay."""

    def test_nonce_values_preserved_after_generation(self):
        """Generated nonces are stored and retrievable for replay."""
        from oida.fuzz.core.session.crypto_state import (
            CryptoStateManager,
            NonceStrategy,
        )

        crypto = CryptoStateManager()
        nonce = crypto.generate_nonce("client_nonce", length=32, strategy=NonceStrategy.RANDOM)

        # Nonce should be retrievable
        retrieved = crypto.get_nonce("client_nonce")
        assert retrieved == nonce
        assert len(retrieved) == 32

    def test_crypto_state_reset_clears_all(self):
        """Reset clears all crypto state for fresh replay iteration."""
        crypto = _make_crypto_state_with_session_data()

        # Verify state is populated
        assert crypto.get_nonce("client_nonce") is not None
        assert crypto.get_nonce("server_nonce") is not None
        assert crypto.get_token_value("security_token") is not None
        assert crypto.get_key("session_key") is not None

        # Reset
        crypto.reset()

        # All state should be cleared
        assert crypto.get_nonce("client_nonce") is None
        assert crypto.get_nonce("server_nonce") is None
        assert crypto.get_token_value("security_token") is None
        assert crypto.get_key("session_key") is None

    def test_key_derivation_reproducible_for_replay(self):
        """Key derivation from stored keys produces identical results."""
        from oida.fuzz.core.session.crypto_state import CryptoStateManager
        import hashlib

        crypto = CryptoStateManager()
        crypto.set_key("master_key", b"master_secret_key_material_here!", algorithm="AES-256")

        def derive(source: bytes) -> bytes:
            return hashlib.sha256(source).digest()

        derived1 = crypto.derive_key("session_key", "master_key", derive, "AES-256-CBC")

        # Reset and re-derive
        master_key = crypto.get_key("master_key")

        crypto2 = CryptoStateManager()
        crypto2.set_key("master_key", master_key, algorithm="AES-256")
        derived2 = crypto2.derive_key("session_key", "master_key", derive, "AES-256-CBC")

        assert derived1 == derived2

    def test_fuzz_override_preserved_for_replay(self):
        """Nonce fuzz overrides are preserved and applied consistently."""
        from oida.fuzz.core.session.crypto_state import (
            CryptoStateManager,
            NonceStrategy,
        )

        crypto = CryptoStateManager()

        # Generate normal nonce
        normal_nonce = crypto.generate_nonce("test_nonce", length=16)

        # Apply zero fuzz override
        crypto.fuzz_nonce("test_nonce", NonceStrategy.ZERO)

        # Override should be applied
        fuzzed = crypto.get_nonce("test_nonce")
        assert fuzzed == b"\x00" * 16

        # Clear override
        crypto.clear_fuzz_override("test_nonce")

        # Should return original value
        restored = crypto.get_nonce("test_nonce")
        assert restored == normal_nonce

    def test_token_expiry_check_during_replay(self):
        """Token expiry is correctly evaluated during replay."""
        from oida.fuzz.core.session.crypto_state import (
            CryptoStateManager,
            TokenState,
        )

        crypto = CryptoStateManager()

        # Token that hasn't expired
        crypto.set_token(
            "valid_token",
            TokenState(
                name="valid_token",
                value="token_value_1",
                expires_at=datetime.now() + timedelta(hours=1),
            ),
        )

        # Token that has already expired
        crypto.set_token(
            "expired_token",
            TokenState(
                name="expired_token",
                value="token_value_2",
                expires_at=datetime.now() - timedelta(hours=1),
            ),
        )

        valid = crypto.get_token("valid_token")
        expired = crypto.get_token("expired_token")

        assert not valid.is_expired()
        assert expired.is_expired()

    def test_crypto_state_in_context_survives_transitions(self):
        """Crypto state attached to StateContext survives state machine transitions."""
        from oida.fuzz.core.session.state_context import StateContext
        from oida.fuzz.core.session.state_machine import (
            ProtocolState,
            StateMachine,
        )
        from oida.fuzz.core.session.crypto_state import (
            NonceStrategy,
        )

        ctx = StateContext()

        def setup_tls(context):
            # During TLS setup, generate nonces
            context.crypto.generate_nonce("client_nonce", length=32, strategy=NonceStrategy.RANDOM)
            context.crypto.set_nonce("server_nonce", b"\x11\x22\x33\x44" * 8)
            context.crypto.set_key("session_key", b"\x00" * 32, "AES-256-CBC")
            return True

        def setup_auth(context):
            # Auth uses nonces from TLS phase
            client_nonce = context.crypto.get_nonce("client_nonce")
            server_nonce = context.crypto.get_nonce("server_nonce")
            assert client_nonce is not None
            assert server_nonce is not None
            context.set("auth_complete", True)
            return True

        sm = StateMachine(
            initial_state=ProtocolState(name="CONNECTED"),
            states=[
                ProtocolState(name="CONNECTED"),
                ProtocolState(
                    name="TLS",
                    setup=setup_tls,
                    requires=["CONNECTED"],
                ),
                ProtocolState(
                    name="AUTHENTICATED",
                    setup=setup_auth,
                    requires=["TLS"],
                ),
            ],
            context=ctx,
        )

        sm.transition_to("TLS")
        sm.transition_to("AUTHENTICATED")

        # Crypto state should be fully intact
        assert ctx.crypto.get_nonce("client_nonce") is not None
        assert ctx.crypto.get_nonce("server_nonce") == b"\x11\x22\x33\x44" * 8
        assert ctx.crypto.get_key("session_key") == b"\x00" * 32
        assert ctx.get("auth_complete") is True


# =============================================================================
# Test Sequence Number Tracking Across Replay
# =============================================================================


class TestSequenceReplay:
    """Verify sequence numbers are correctly handled during replay."""

    def test_sequence_reset_for_replay(self):
        """Sequence manager reset restores initial values for replay."""
        mgr = _make_sequence_manager_with_state()

        # Verify sequences have advanced
        assert mgr.get("send_seq") == 20  # 10 increments * 2
        assert mgr.get("recv_seq") == 16  # 8 increments * 2

        # Reset for replay
        mgr.reset()

        # Back to initial values
        assert mgr.get("send_seq") == 0
        assert mgr.get("recv_seq") == 0

    def test_sequence_replay_produces_identical_values(self):
        """Replaying the same increment pattern produces identical sequence values."""
        from oida.fuzz.core.session.sequence import SequenceManager, SequenceConfig

        def run_sequence_pattern(mgr):
            """Run a specific pattern of sequence operations."""
            values = []
            for _ in range(5):
                values.append(mgr.get_and_increment("send_seq"))
                values.append(mgr.get_and_increment("recv_seq"))
            values.append(mgr.get_and_increment("send_seq"))
            return values

        # First run
        mgr1 = SequenceManager("test")
        mgr1.add_sequence(SequenceConfig(name="send_seq", initial=0, increment=2, max_value=0xFFFF))
        mgr1.add_sequence(SequenceConfig(name="recv_seq", initial=0, increment=2, max_value=0xFFFF))
        values1 = run_sequence_pattern(mgr1)

        # Replay run
        mgr2 = SequenceManager("test")
        mgr2.add_sequence(SequenceConfig(name="send_seq", initial=0, increment=2, max_value=0xFFFF))
        mgr2.add_sequence(SequenceConfig(name="recv_seq", initial=0, increment=2, max_value=0xFFFF))
        values2 = run_sequence_pattern(mgr2)

        assert values1 == values2

    def test_sequence_wrapping_during_replay(self):
        """Sequence wrapping behaves identically during replay."""
        from oida.fuzz.core.session.sequence import SequenceManager, SequenceConfig

        def run_wrap_scenario(mgr):
            values = []
            for _ in range(12):
                values.append(mgr.get_and_increment("seq"))
            return values

        mgr1 = SequenceManager()
        mgr1.add_sequence(
            SequenceConfig(name="seq", initial=8, increment=1, min_value=0, max_value=10)
        )
        values1 = run_wrap_scenario(mgr1)

        mgr2 = SequenceManager()
        mgr2.add_sequence(
            SequenceConfig(name="seq", initial=8, increment=1, min_value=0, max_value=10)
        )
        values2 = run_wrap_scenario(mgr2)

        assert values1 == values2
        # Should contain wrap-around values
        assert 10 in values1
        assert 0 in values1

    def test_sequence_manager_in_context_survives_state_transitions(self):
        """Sequence manager attached to context survives state transitions."""
        from oida.fuzz.core.session.state_context import StateContext
        from oida.fuzz.core.session.state_machine import (
            ProtocolState,
            StateMachine,
        )
        from oida.fuzz.core.session.sequence import SequenceConfig

        ctx = StateContext()

        def setup_connected(context):
            seq_mgr = context.get_sequence_manager("protocol")
            seq_mgr.add_sequence(SequenceConfig(name="transaction_id", initial=1, max_value=0xFFFF))
            return True

        def setup_command(context):
            seq_mgr = context.get_sequence_manager("protocol")
            tid = seq_mgr.get_and_increment("transaction_id")
            context.set("last_tid", tid)
            return True

        sm = StateMachine(
            initial_state=ProtocolState(name="IDLE"),
            states=[
                ProtocolState(name="IDLE"),
                ProtocolState(name="CONNECTED", setup=setup_connected, requires=["IDLE"]),
                ProtocolState(name="COMMAND_SENT", setup=setup_command, requires=["CONNECTED"]),
            ],
            context=ctx,
        )

        sm.transition_to("CONNECTED")
        sm.transition_to("COMMAND_SENT")

        assert ctx.get("last_tid") == 1
        assert ctx.get_sequence_manager("protocol").get("transaction_id") == 2


# =============================================================================
# Test Database-Backed Replay with State
# =============================================================================


class TestDatabaseReplay:
    """Verify replay from database with session state."""

    def test_rolling_buffer_captures_crash_context(self):
        """Rolling buffer correctly captures test case history for crash context."""
        from oida.fuzz.core.session.manager import RollingBuffer

        buffer = RollingBuffer(maxsize=50)

        # Simulate 30 test cases
        for i in range(1, 31):
            payload = f"test_payload_{i}".encode()
            crc = binascii.crc32(payload) & 0xFFFFFFFF
            buffer.add(i, f"test_{i}", payload, datetime.now().isoformat(), crc)

        assert buffer.buffer_size == 30
        assert buffer.total_count == 30
        assert buffer.latest_id == 30

        # Get all buffered content (as crash context)
        context = buffer.get_all()
        assert len(context) == 30
        assert context[0][0] == 1  # First ID
        assert context[-1][0] == 30  # Last ID

    def test_rolling_buffer_evicts_old_entries(self):
        """Rolling buffer correctly evicts oldest entries when full."""
        from oida.fuzz.core.session.manager import RollingBuffer

        buffer = RollingBuffer(maxsize=10)

        # Add 25 entries - should only keep last 10
        for i in range(1, 26):
            payload = f"payload_{i}".encode()
            crc = binascii.crc32(payload) & 0xFFFFFFFF
            buffer.add(i, f"test_{i}", payload, datetime.now().isoformat(), crc)

        assert buffer.buffer_size == 10
        assert buffer.total_count == 25

        context = buffer.get_all()
        # Should contain IDs 16-25 (last 10)
        ids = [entry[0] for entry in context]
        assert ids == list(range(16, 26))

    def test_rolling_buffer_clear_and_refill(self):
        """Rolling buffer can be cleared and refilled for replay."""
        from oida.fuzz.core.session.manager import RollingBuffer

        buffer = RollingBuffer(maxsize=20)

        # First fill
        for i in range(1, 11):
            buffer.add(i, f"test_{i}", b"payload", datetime.now().isoformat(), 0)

        assert buffer.buffer_size == 10

        # Clear for replay
        buffer.clear()
        assert buffer.buffer_size == 0
        # total_count is NOT reset by clear (it's a lifetime counter)
        assert buffer.total_count == 10

        # Refill during replay
        for i in range(1, 6):
            buffer.add(i, f"replay_{i}", b"replay_payload", datetime.now().isoformat(), 0)

        assert buffer.buffer_size == 5
        context = buffer.get_all()
        assert context[0][1] == "replay_1"

    def test_database_store_and_retrieve_crash_payload(self):
        """Database correctly stores and retrieves crash payloads for replay."""
        _setup_logging_context()
        from oida.fuzz.core.database.orm import SQLAlchemyDatabase
        from oida.fuzz.core.database.interface import TestCase, Crash

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            db = SQLAlchemyDatabase(db_path)
            db.init_schema()

            # Store test case
            test_case = TestCase(
                id=1,
                name="crash_test",
                timestamp=datetime.now().isoformat(),
                result="crash",
                crc32=0xDEADBEEF,
                target_ip="127.0.0.1",
                target_port=502,
                protocol="modbus",
            )
            db.store_test_case(test_case)

            # Store crash with payload
            crash_payload = b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x0a"
            crash = Crash(
                test_case_id=1,
                payload=crash_payload,
                crash_info="Segfault in modbus_process_request",
            )
            db.store_crash(crash)

            # Retrieve for replay
            retrieved_case = db.get_test_case(1)
            retrieved_crash = db.get_crash(1)

            assert retrieved_case is not None
            assert retrieved_case.result == "crash"
            assert retrieved_case.crc32 == 0xDEADBEEF

            assert retrieved_crash is not None
            assert retrieved_crash.payload == crash_payload
            assert "Segfault" in retrieved_crash.crash_info

            db.close()

    def test_database_metadata_for_replay_validation(self):
        """Session metadata is stored correctly for replay validation."""
        _setup_logging_context()
        from oida.fuzz.core.database.orm import SQLAlchemyDatabase

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            db = SQLAlchemyDatabase(db_path)
            db.init_schema()

            # Store replay-relevant metadata
            db.store_metadata("protocol_name", "modbus")
            db.store_metadata("protocol_version", "abc123def")
            db.store_metadata("seed", "42")
            db.store_metadata("last_test_case", "1000")
            db.store_metadata("total_processed", "1000")
            db.store_metadata("crash_count", "3")

            # Retrieve for replay validation
            assert db.get_metadata("protocol_name") == "modbus"
            assert db.get_metadata("protocol_version") == "abc123def"
            assert db.get_metadata("seed") == "42"
            assert db.get_metadata("last_test_case") == "1000"
            assert db.get_metadata("crash_count") == "3"

            # All metadata
            all_meta = db.get_all_metadata()
            assert "protocol_name" in all_meta
            assert "protocol_version" in all_meta

            db.close()

    def test_database_multiple_crashes_with_context(self):
        """Database handles multiple crashes with overlapping buffer contexts."""
        _setup_logging_context()
        from oida.fuzz.core.database.orm import SQLAlchemyDatabase
        from oida.fuzz.core.database.interface import TestCase, Crash

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            db = SQLAlchemyDatabase(db_path)
            db.init_schema()

            # Simulate two crashes with context
            for crash_id in [50, 100]:
                # Store context test cases around crash
                for i in range(crash_id - 5, crash_id + 1):
                    tc = TestCase(
                        id=i,
                        name=f"test_{i}",
                        timestamp=datetime.now().isoformat(),
                        result="crash" if i == crash_id else "pass",
                        crc32=binascii.crc32(f"payload_{i}".encode()) & 0xFFFFFFFF,
                        target_ip="127.0.0.1",
                        target_port=502,
                        protocol="modbus",
                    )
                    db.store_test_case(tc)

                # Store crash payload
                crash = Crash(
                    test_case_id=crash_id,
                    payload=f"crash_payload_{crash_id}".encode(),
                    crash_info=f"Crash at test case {crash_id}",
                )
                db.store_crash(crash)

            # Both crashes should be retrievable
            crash1 = db.get_crash(50)
            crash2 = db.get_crash(100)

            assert crash1 is not None
            assert crash2 is not None
            assert crash1.payload == b"crash_payload_50"
            assert crash2.payload == b"crash_payload_100"

            # Context test cases should also be present
            case_49 = db.get_test_case(49)
            case_99 = db.get_test_case(99)
            assert case_49 is not None
            assert case_49.result == "pass"
            assert case_99 is not None
            assert case_99.result == "pass"

            db.close()

    def test_crc32_validation_for_replay(self):
        """CRC32 validation catches payload corruption during replay."""
        payload = b"\x00\x01\x02\x03\x04\x05\x06\x07"
        expected_crc = binascii.crc32(payload) & 0xFFFFFFFF

        # Correct payload
        actual_crc = binascii.crc32(payload) & 0xFFFFFFFF
        assert actual_crc == expected_crc

        # Corrupted payload (1 bit flip)
        corrupted = bytearray(payload)
        corrupted[3] ^= 0x01
        corrupted_crc = binascii.crc32(bytes(corrupted)) & 0xFFFFFFFF
        assert corrupted_crc != expected_crc


# =============================================================================
# Test Edge Cases: Interrupted Sessions, Partial Sequences, State Rollback
# =============================================================================


class TestReplayEdgeCases:
    """Edge cases for replay correctness."""

    def test_interrupted_session_partial_buffer(self):
        """Interrupted session with partially filled buffer is handled."""
        from oida.fuzz.core.session.manager import RollingBuffer

        buffer = RollingBuffer(maxsize=100)

        # Only 3 test cases before "interruption"
        for i in range(1, 4):
            payload = f"payload_{i}".encode()
            crc = binascii.crc32(payload) & 0xFFFFFFFF
            buffer.add(i, f"test_{i}", payload, datetime.now().isoformat(), crc)

        # Buffer should have what we put in
        assert buffer.buffer_size == 3
        context = buffer.get_all()
        assert len(context) == 3

    def test_empty_buffer_crash(self):
        """Empty buffer at crash time returns empty context."""
        from oida.fuzz.core.session.manager import RollingBuffer

        buffer = RollingBuffer(maxsize=100)
        assert buffer.buffer_size == 0
        assert buffer.get_all() == []

    def test_state_machine_reset_after_error_state(self):
        """State machine can reset from error state for replay."""
        from oida.fuzz.core.session.state_machine import (
            ProtocolState,
            StateMachine,
            StateType,
        )

        error_state = ProtocolState(
            name="ERROR", state_type=StateType.ERROR, description="Error occurred"
        )
        sm = StateMachine(
            initial_state=ProtocolState(name="CONNECTED"),
            states=[
                ProtocolState(name="CONNECTED"),
                ProtocolState(name="COMMAND_SENT", requires=["CONNECTED"]),
                error_state,
            ],
            allow_invalid_transitions=True,
        )

        # Transition to error state
        sm.transition_to("COMMAND_SENT")
        sm.transition_to("ERROR")
        assert sm.get_current_state_name() == "ERROR"

        # Reset for replay
        sm.reset()
        assert sm.get_current_state_name() == "CONNECTED"

        # Can re-traverse normally
        sm.transition_to("COMMAND_SENT")
        assert sm.get_current_state_name() == "COMMAND_SENT"

    def test_state_rollback_on_transition_failure(self):
        """State machine stays in current state if transition setup fails."""
        from oida.fuzz.core.session.state_machine import (
            ProtocolState,
            StateMachine,
            StateTransitionError,
        )

        def failing_setup():
            return False

        sm = StateMachine(
            initial_state=ProtocolState(name="CONNECTED"),
            states=[
                ProtocolState(name="CONNECTED"),
                ProtocolState(
                    name="AUTH_FAILED",
                    setup=failing_setup,
                    requires=["CONNECTED"],
                ),
            ],
        )

        with pytest.raises(StateTransitionError, match="Failed to enter state"):
            sm.transition_to("AUTH_FAILED")

        # Should still be in CONNECTED
        assert sm.get_current_state_name() == "CONNECTED"

    def test_forced_transition_for_replay_attack_testing(self):
        """Forced transitions work for replay of attack scenarios."""
        sm = _make_multi_step_state_machine()

        # Normal path: must go DISCONNECTED -> CONNECTED -> ...
        # Force jump directly to AUTHENTICATED (invalid but useful for attack replay)
        sm.transition_to("AUTHENTICATED", force=True)
        assert sm.get_current_state_name() == "AUTHENTICATED"

    def test_replay_with_timeout_state(self):
        """States with timeouts can be replayed without timing issues."""
        from oida.fuzz.core.session.state_machine import (
            ProtocolState,
            StateMachine,
            StateType,
        )

        timeout_state = ProtocolState(
            name="WAITING",
            state_type=StateType.TRANSACTION,
            requires=["CONNECTED"],
            timeout=0.001,  # Very short timeout
            description="Waiting for response",
        )

        sm = StateMachine(
            initial_state=ProtocolState(name="CONNECTED"),
            states=[
                ProtocolState(name="CONNECTED"),
                timeout_state,
                ProtocolState(name="RESPONSE_RECEIVED", requires=["WAITING"]),
            ],
        )

        sm.transition_to("WAITING")
        # Wait for timeout to expire
        time.sleep(0.01)
        assert sm.current_state.is_timed_out()

        # Can still transition away from timed-out state
        sm.transition_to("RESPONSE_RECEIVED")
        assert sm.get_current_state_name() == "RESPONSE_RECEIVED"

    def test_transition_log_captures_replay_metadata(self):
        """Transition log captures timestamps and forced-flags for replay analysis."""
        sm = _make_multi_step_state_machine()

        sm.transition_to("CONNECTED")
        sm.transition_to("TLS_ESTABLISHED")
        sm.transition_to("AUTHENTICATED", force=True)

        log = sm.get_transition_log()
        assert len(log) == 3

        # First two transitions are normal
        assert log[0]["from"] == "DISCONNECTED"
        assert log[0]["to"] == "CONNECTED"
        assert log[0]["forced"] is False
        assert "timestamp" in log[0]

        # Third is forced
        assert log[2]["forced"] is True

    def test_on_enter_on_exit_callbacks_during_replay(self):
        """on_enter and on_exit callbacks fire during replay transitions."""
        from oida.fuzz.core.session.state_machine import (
            ProtocolState,
            StateMachine,
        )

        events = []

        connected = ProtocolState(
            name="CONNECTED",
            on_enter=lambda: events.append("enter_connected"),
            on_exit=lambda: events.append("exit_connected"),
        )
        authenticated = ProtocolState(
            name="AUTHENTICATED",
            on_enter=lambda: events.append("enter_auth"),
            on_exit=lambda: events.append("exit_auth"),
            requires=["CONNECTED"],
        )

        sm = StateMachine(
            initial_state=ProtocolState(name="IDLE"),
            states=[
                ProtocolState(name="IDLE"),
                connected,
                authenticated,
            ],
        )

        sm.transition_to("CONNECTED")
        sm.transition_to("AUTHENTICATED")

        # on_exit for IDLE, on_enter for CONNECTED
        # on_exit for CONNECTED, on_enter for AUTHENTICATED
        assert "enter_connected" in events
        assert "exit_connected" in events
        assert "enter_auth" in events

    def test_state_validation_during_replay(self):
        """State validation callbacks work during replay."""
        from oida.fuzz.core.session.state_machine import (
            ProtocolState,
            StateMachine,
        )

        validation_ok = True

        def validate_connected():
            return validation_ok

        sm = StateMachine(
            initial_state=ProtocolState(name="IDLE"),
            states=[
                ProtocolState(name="IDLE"),
                ProtocolState(
                    name="CONNECTED",
                    validation=validate_connected,
                    requires=["IDLE"],
                ),
            ],
        )

        sm.transition_to("CONNECTED")

        # Validation passes
        assert sm.validate_current_state() is True

        # Simulate connection loss
        validation_ok = False
        assert sm.validate_current_state() is False


# =============================================================================
# Test Full Replay Scenario Integration
# =============================================================================


class TestFullReplayScenario:
    """End-to-end replay scenario tests combining multiple components."""

    def test_full_handshake_replay_with_context_and_crypto(self):
        """Complete handshake replay scenario with context and crypto state.

        Simulates: IDLE -> CONNECTED -> TLS -> AUTHENTICATED -> COMMAND_SENT
        with crypto nonces, sequence numbers, and response data.
        """
        from oida.fuzz.core.session.state_context import StateContext, ResponseData
        from oida.fuzz.core.session.state_machine import (
            ProtocolState,
            StateMachine,
        )
        from oida.fuzz.core.session.sequence import SequenceConfig
        from oida.fuzz.core.session.crypto_state import NonceStrategy

        # Set up context with sequence manager
        ctx = StateContext()
        seq_mgr = ctx.get_sequence_manager("protocol")
        seq_mgr.add_sequence(SequenceConfig(name="msg_id", initial=1, max_value=0xFFFFFFFF))

        # Define state callbacks
        def setup_connected(context):
            context.set_response(
                "CONNECT",
                ResponseData(
                    raw=b"\x00\x01",
                    parsed={"server_version": "2.0"},
                    response_code=200,
                ),
            )
            return True

        def setup_tls(context):
            context.crypto.generate_nonce("client_nonce", 32, NonceStrategy.RANDOM)
            context.crypto.set_nonce("server_nonce", b"\xaa" * 32)
            context.crypto.set_key("session_key", b"\xbb" * 32, "AES-256-CBC")
            context.set("tls_version", "TLS_1.3")
            return True

        def setup_auth(context):
            msg_id = context.get_sequence_manager("protocol").get_and_increment("msg_id")
            context.set("auth_msg_id", msg_id)
            context.set("auth_token", "replay_token_abc")
            context.set_response(
                "AUTH",
                ResponseData(
                    raw=b"\x00\x02",
                    parsed={"token": "replay_token_abc", "expires_in": 3600},
                    response_code=200,
                ),
            )
            return True

        def setup_command(context):
            msg_id = context.get_sequence_manager("protocol").get_and_increment("msg_id")
            context.set("command_msg_id", msg_id)
            return True

        sm = StateMachine(
            initial_state=ProtocolState(name="IDLE"),
            states=[
                ProtocolState(name="IDLE"),
                ProtocolState(name="CONNECTED", setup=setup_connected, requires=["IDLE"]),
                ProtocolState(name="TLS", setup=setup_tls, requires=["CONNECTED"]),
                ProtocolState(name="AUTHENTICATED", setup=setup_auth, requires=["TLS"]),
                ProtocolState(
                    name="COMMAND_SENT",
                    setup=setup_command,
                    requires=["AUTHENTICATED"],
                ),
            ],
            context=ctx,
        )

        # First run
        sm.traverse_to_state("COMMAND_SENT")
        first_run = {
            "history": sm.get_state_history(),
            "auth_msg_id": ctx.get("auth_msg_id"),
            "command_msg_id": ctx.get("command_msg_id"),
            "tls_version": ctx.get("tls_version"),
            "auth_token": ctx.get("auth_token"),
            "server_version": ctx.get_response("CONNECT").parsed["server_version"],
            "client_nonce": ctx.crypto.get_nonce("client_nonce"),
            "session_key": ctx.crypto.get_key("session_key"),
        }

        # Verify first run
        assert first_run["history"] == [
            "IDLE",
            "CONNECTED",
            "TLS",
            "AUTHENTICATED",
            "COMMAND_SENT",
        ]
        assert first_run["auth_msg_id"] == 1
        assert first_run["command_msg_id"] == 2
        assert first_run["tls_version"] == "TLS_1.3"
        assert first_run["auth_token"] == "replay_token_abc"

        # Replay: reset state machine and context, run again
        sm.reset()
        ctx.clear()
        ctx.crypto.reset()
        seq_mgr = ctx.get_sequence_manager("protocol")
        seq_mgr.reset()

        sm.traverse_to_state("COMMAND_SENT")
        replay_run = {
            "history": sm.get_state_history(),
            "auth_msg_id": ctx.get("auth_msg_id"),
            "command_msg_id": ctx.get("command_msg_id"),
            "tls_version": ctx.get("tls_version"),
            "auth_token": ctx.get("auth_token"),
            "server_version": ctx.get_response("CONNECT").parsed["server_version"],
            "session_key": ctx.crypto.get_key("session_key"),
        }

        # Replay should match first run (except nonces which are random)
        assert replay_run["history"] == first_run["history"]
        assert replay_run["auth_msg_id"] == first_run["auth_msg_id"]
        assert replay_run["command_msg_id"] == first_run["command_msg_id"]
        assert replay_run["tls_version"] == first_run["tls_version"]
        assert replay_run["auth_token"] == first_run["auth_token"]
        assert replay_run["server_version"] == first_run["server_version"]
        assert replay_run["session_key"] == first_run["session_key"]

    def test_replay_with_database_crash_context(self):
        """Simulate recording a crash and replaying it from database."""
        _setup_logging_context()
        from oida.fuzz.core.session.manager import RollingBuffer
        from oida.fuzz.core.database.orm import SQLAlchemyDatabase
        from oida.fuzz.core.database.interface import TestCase, Crash

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "replay_test.db")
            db = SQLAlchemyDatabase(db_path)
            db.init_schema()

            # Phase 1: Record fuzzing session with rolling buffer
            buffer = RollingBuffer(maxsize=20)

            payloads = {}
            for i in range(1, 16):
                payload = bytes([i] * 10)
                crc = binascii.crc32(payload) & 0xFFFFFFFF
                payloads[i] = (payload, crc)
                buffer.add(i, f"modbus_fc{i}", payload, datetime.now().isoformat(), crc)

            # Crash detected at test case 15
            crash_payload = payloads[15][0]

            # Flush buffer to database
            for tc_id, tc_name, tc_payload, tc_ts, tc_crc in buffer.get_all():
                tc = TestCase(
                    id=tc_id,
                    name=tc_name,
                    timestamp=tc_ts,
                    result="crash" if tc_id == 15 else "pass",
                    crc32=tc_crc,
                    target_ip="192.168.1.100",
                    target_port=502,
                    protocol="modbus",
                )
                db.store_test_case(tc)

            crash = Crash(
                test_case_id=15,
                payload=crash_payload,
                crash_info="Modbus exception: illegal function code",
            )
            db.store_crash(crash)

            # Phase 2: Replay from database
            # Retrieve crash
            retrieved_crash = db.get_crash(15)
            assert retrieved_crash is not None
            assert retrieved_crash.payload == crash_payload

            # Validate CRC
            replay_crc = binascii.crc32(retrieved_crash.payload) & 0xFFFFFFFF
            expected_crc = payloads[15][1]
            assert replay_crc == expected_crc

            # Retrieve context (test cases leading up to crash)
            all_cases = db.get_test_cases()
            crash_cases = [c for c in all_cases if c.result == "crash"]
            context_cases = [c for c in all_cases if c.result == "pass"]

            assert len(crash_cases) == 1
            assert len(context_cases) == 14  # 14 passing before crash

            db.close()

    def test_topological_state_order_for_replay_planning(self):
        """Topological ordering gives correct replay sequence."""
        sm = _make_multi_step_state_machine()

        order = sm.get_topological_order()

        # DISCONNECTED should come first (no dependencies)
        assert order[0] == "DISCONNECTED"

        # Each state should come after its dependencies
        for i, state_name in enumerate(order):
            state = sm.states[state_name]
            for req in state.requires:
                req_idx = order.index(req)
                assert req_idx < i, f"{state_name} requires {req} but {req} comes after it in order"

    def test_transition_rules_with_conditions_during_replay(self):
        """Transition rules with conditions are evaluated during replay."""
        from oida.fuzz.core.session.state_machine import (
            ProtocolState,
            StateMachine,
            TransitionRule,
            StateTransitionError,
        )

        # Condition: only allow auth if we have credentials
        has_credentials = True

        def check_credentials():
            return has_credentials

        action_log = []

        def log_auth_attempt():
            action_log.append("auth_attempted")

        connected = ProtocolState(name="CONNECTED")
        authenticated = ProtocolState(name="AUTHENTICATED")

        rule = TransitionRule(
            from_state="CONNECTED",
            to_state="AUTHENTICATED",
            condition=check_credentials,
            action=log_auth_attempt,
            description="Authenticate with credentials",
        )

        sm = StateMachine(
            initial_state=connected,
            states=[connected, authenticated],
            transitions=[rule],
        )

        # With credentials: transition should work
        sm.transition_to("AUTHENTICATED")
        assert sm.get_current_state_name() == "AUTHENTICATED"
        assert "auth_attempted" in action_log

        # Reset for replay without credentials
        sm.reset()
        action_log.clear()
        has_credentials = False

        with pytest.raises(StateTransitionError):
            sm.transition_to("AUTHENTICATED")

        # Should still be in CONNECTED
        assert sm.get_current_state_name() == "CONNECTED"

    def test_hierarchical_states_during_replay(self):
        """Hierarchical (parent/child) protocol states work during replay."""
        from oida.fuzz.core.session.state_machine import (
            ProtocolState,
            StateType,
        )

        # Parent state: DATA_TRANSFER
        data_transfer = ProtocolState(
            name="DATA_TRANSFER",
            state_type=StateType.DATA_TRANSFER,
        )

        # Child states under DATA_TRANSFER
        active_mode = ProtocolState(
            name="ACTIVE_MODE",
            state_type=StateType.DATA_TRANSFER,
            parent=data_transfer,
        )
        passive_mode = ProtocolState(
            name="PASSIVE_MODE",
            state_type=StateType.DATA_TRANSFER,
            parent=data_transfer,
        )

        # Verify parent-child relationships
        assert active_mode.parent is data_transfer
        assert passive_mode.parent is data_transfer
        assert active_mode in data_transfer.children
        assert passive_mode in data_transfer.children

        # Ancestor checks
        assert active_mode.is_descendant_of(data_transfer)
        assert not data_transfer.is_descendant_of(active_mode)

    def test_context_to_dict_captures_replay_state(self):
        """StateContext serialization captures all state needed for replay debugging."""
        from oida.fuzz.core.session.state_context import StateContext, ResponseData
        from oida.fuzz.core.session.sequence import SequenceConfig

        ctx = StateContext()
        ctx.set("channel_id", 42)
        ctx.set("auth_token", "tok123")
        ctx.set_response("HELLO", ResponseData(raw=b"\x01"))
        ctx.set_response("AUTH", ResponseData(raw=b"\x02"))

        seq_mgr = ctx.get_sequence_manager("proto")
        seq_mgr.add_sequence(SequenceConfig(name="seq1", initial=0))

        _ = ctx.crypto  # Initialize crypto

        d = ctx.to_dict()

        # All state should be captured
        assert "channel_id" in d["data"]
        assert "auth_token" in d["data"]
        assert "HELLO" in d["responses"]
        assert "AUTH" in d["responses"]
        assert "proto" in d["sequences"]
        assert d["has_crypto"] is True
        assert d["has_parent"] is False
        assert d["depth"] == 0

    def test_crash_event_storage_and_retrieval(self):
        """CrashEvent with context is stored and retrievable for analysis."""
        _setup_logging_context()
        from oida.fuzz.core.database.orm import SQLAlchemyDatabase

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "crash_events.db")
            db = SQLAlchemyDatabase(db_path)
            db.init_schema()

            # Store crash event with buffer context
            buffer_contents = [
                (i, f"test_{i}", bytes([i] * 5), datetime.now().isoformat(), i * 1000)
                for i in range(95, 101)
            ]

            event_id = db.store_crash_context(
                detected_at_id=100,
                crash_info="Buffer overflow in packet parser",
                target_ip="10.0.0.1",
                target_port=44818,
                protocol="ethernetip",
                buffer_contents=buffer_contents,
            )

            # Retrieve crash event
            event = db.get_crash_event(event_id)
            assert event is not None
            assert event["event"]["detected_at_id"] == 100
            assert event["event"]["protocol"] == "ethernetip"
            assert event["event"]["context_size"] == 6
            assert len(event["context"]) == 6

            # Retrieve specific payload from context
            payload = db.get_crash_context_payload(event_id, 98)
            assert payload == bytes([98] * 5)

            db.close()
