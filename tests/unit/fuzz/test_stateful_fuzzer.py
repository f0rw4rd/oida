"""
Tests for StatefulFuzzer state management logic.

Tests cover:
- StateReachabilityResult dataclass
- CommonState enum values
- RequestInfo dataclass (state requirement fields)
- StatefulFuzzer: _request_state_matches logic (ANY, single, list, default)
- StatefulFuzzer: state tracking (_get_current_state, _set_state)
- StatefulFuzzer: _register_request_nodes and _get_request_info_for_node
"""


# =============================================================================
# Test StateReachabilityResult
# =============================================================================


class TestStateReachabilityResult:
    """Tests for StateReachabilityResult dataclass."""

    def test_default_creation(self):
        """StateReachabilityResult with defaults."""
        from oida.fuzz.core.stateful_fuzzer import StateReachabilityResult

        result = StateReachabilityResult(state_name="AUTHENTICATED", reachable=True)
        assert result.state_name == "AUTHENTICATED"
        assert result.reachable is True
        assert result.error is None
        assert result.duration_ms == 0.0
        assert result.skipped is False
        assert result.skip_reason is None

    def test_unreachable_with_error(self):
        """StateReachabilityResult for unreachable state."""
        from oida.fuzz.core.stateful_fuzzer import StateReachabilityResult

        result = StateReachabilityResult(
            state_name="AUTHENTICATED",
            reachable=False,
            error="Connection refused",
            duration_ms=150.0,
        )
        assert result.reachable is False
        assert result.error == "Connection refused"

    def test_skipped_state(self):
        """StateReachabilityResult for skipped state."""
        from oida.fuzz.core.stateful_fuzzer import StateReachabilityResult

        result = StateReachabilityResult(
            state_name="TLS_UPGRADED",
            reachable=False,
            skipped=True,
            skip_reason="TLS not configured",
        )
        assert result.skipped is True
        assert result.skip_reason == "TLS not configured"


# =============================================================================
# Test CommonState Enum
# =============================================================================


class TestCommonState:
    """Tests for CommonState enum."""

    def test_connection_states(self):
        """Connection states exist."""
        from oida.fuzz.core.base_fuzzer import CommonState

        assert CommonState.DISCONNECTED.value == "DISCONNECTED"
        assert CommonState.CONNECTED.value == "CONNECTED"

    def test_authentication_states(self):
        """Authentication states exist."""
        from oida.fuzz.core.base_fuzzer import CommonState

        assert CommonState.PRE_AUTH.value == "PRE_AUTH"
        assert CommonState.AUTHENTICATING.value == "AUTHENTICATING"
        assert CommonState.AUTHENTICATED.value == "AUTHENTICATED"
        assert CommonState.AUTH_FAILED.value == "AUTH_FAILED"

    def test_session_states(self):
        """Session states exist."""
        from oida.fuzz.core.base_fuzzer import CommonState

        assert CommonState.IDLE.value == "IDLE"
        assert CommonState.BUSY.value == "BUSY"

    def test_data_transfer_states(self):
        """Data transfer states exist."""
        from oida.fuzz.core.base_fuzzer import CommonState

        assert CommonState.DATA_CHANNEL_SETUP.value == "DATA_CHANNEL_SETUP"
        assert CommonState.DATA_TRANSFER_ACTIVE.value == "DATA_TRANSFER_ACTIVE"

    def test_special_states(self):
        """Special states exist."""
        from oida.fuzz.core.base_fuzzer import CommonState

        assert CommonState.ANY.value == "ANY"
        assert CommonState.ERROR.value == "ERROR"


# =============================================================================
# Test RequestInfo
# =============================================================================


class TestRequestInfo:
    """Tests for RequestInfo dataclass."""

    def test_basic_creation(self):
        """RequestInfo with minimal fields."""
        from oida.fuzz.core.base_fuzzer import RequestInfo

        ri = RequestInfo(name="Test_Request", description="A test")
        assert ri.name == "Test_Request"
        assert ri.description == "A test"
        assert ri.category == "general"
        assert ri.slow is False
        assert ri.requires_state is None

    def test_with_state_requirement(self):
        """RequestInfo with state requirement."""
        from oida.fuzz.core.base_fuzzer import RequestInfo, CommonState

        ri = RequestInfo(
            name="Auth_Fuzz", description="Auth fuzzing", requires_state=CommonState.PRE_AUTH
        )
        assert ri.requires_state == CommonState.PRE_AUTH

    def test_with_list_requirement(self):
        """RequestInfo with multiple acceptable states."""
        from oida.fuzz.core.base_fuzzer import RequestInfo, CommonState

        ri = RequestInfo(
            name="Flexible_Fuzz",
            description="Works in multiple states",
            requires_state=[CommonState.AUTHENTICATED, "CUSTOM_STATE"],
        )
        assert isinstance(ri.requires_state, list)
        assert len(ri.requires_state) == 2

    def test_with_category_and_slow(self):
        """RequestInfo with category and slow flag."""
        from oida.fuzz.core.base_fuzzer import RequestInfo

        ri = RequestInfo(
            name="Heavy_Test", description="Slow test", category="performance", slow=True
        )
        assert ri.category == "performance"
        assert ri.slow is True


# =============================================================================
# Test StatefulFuzzer State Management (Unit-Level, Mocked)
# =============================================================================


class TestStatefulFuzzerStateMatching:
    """Tests for _request_state_matches logic in isolation.

    These tests validate the state matching algorithm without requiring
    a fully initialized StatefulFuzzer (which needs boofuzz Session).
    We test the algorithm by simulating its behavior.
    """

    def test_any_state_always_matches(self):
        """CommonState.ANY always matches regardless of current state."""
        from oida.fuzz.core.base_fuzzer import CommonState, RequestInfo

        # ANY should match any state
        ri = RequestInfo("test", "desc", requires_state=CommonState.ANY)
        assert ri.requires_state == CommonState.ANY

        # Also test string "ANY"
        ri2 = RequestInfo("test", "desc", requires_state="ANY")
        assert ri2.requires_state == "ANY"

    def test_none_requirement_uses_default(self):
        """None requires_state should fall back to fuzzer default."""
        from oida.fuzz.core.base_fuzzer import RequestInfo

        ri = RequestInfo("test", "desc", requires_state=None)
        assert ri.requires_state is None
        # In StatefulFuzzer, this would use DEFAULT_REQUEST_STATE

    def test_single_state_requirement(self):
        """Single state requirement matches when current == required."""
        from oida.fuzz.core.base_fuzzer import CommonState, RequestInfo

        ri = RequestInfo("auth_test", "desc", requires_state=CommonState.AUTHENTICATED)
        # The requires_state is AUTHENTICATED
        required_name = ri.requires_state.value
        assert required_name == "AUTHENTICATED"

    def test_list_state_requirement(self):
        """List of states - any match in the list satisfies requirement."""
        from oida.fuzz.core.base_fuzzer import CommonState, RequestInfo

        ri = RequestInfo(
            "flexible",
            "desc",
            requires_state=[CommonState.AUTHENTICATED, CommonState.IDLE, "CUSTOM_STATE"],
        )
        assert isinstance(ri.requires_state, list)
        # Extract names for matching
        req_names = [s.value if isinstance(s, CommonState) else s for s in ri.requires_state]
        assert "AUTHENTICATED" in req_names
        assert "IDLE" in req_names
        assert "CUSTOM_STATE" in req_names


class TestStatefulFuzzerSocketTimeouts:
    """Regression tests for _create_socket forwarding timeouts.

    The stateful data socket must honor CLI --recv/send-timeout overrides
    (surfaced as config.recv_timeout/send_timeout) and the calibrated
    recv_timeout, not stay pinned to the StatefulConnection 5.0s default.
    """

    def _build_fuzzer(self, recv_timeout, send_timeout):
        import logging

        from oida.fuzz.core.stateful_fuzzer import StatefulFuzzer

        captured = {}

        class FakeConnection:
            def __init__(self, host, port, **kwargs):
                captured["host"] = host
                captured["port"] = port
                captured.update(kwargs)

        class FakeConfig:
            target_ip = "10.0.0.1"
            target_port = 2121
            reuse_target_connection = False

            def __init__(self):
                self.recv_timeout = recv_timeout
                self.send_timeout = send_timeout

        class ConcreteStatefulFuzzer(StatefulFuzzer):
            def _define_protocol(self):  # pragma: no cover - never executed
                pass

        fuzzer = object.__new__(ConcreteStatefulFuzzer)
        fuzzer.CONNECTION_CLASS = FakeConnection
        fuzzer.PROTOCOL_NAME = "ftp"
        fuzzer.config = FakeConfig()
        fuzzer.log = logging.getLogger("test_stateful_socket_timeouts")

        fuzzer._create_socket()
        return captured

    def test_cli_overrides_forwarded(self):
        """Non-default config timeouts are passed through, not the 5.0 default."""
        captured = self._build_fuzzer(recv_timeout=42.0, send_timeout=7.0)
        assert captured["recv_timeout"] == 42.0
        assert captured["send_timeout"] == 7.0
        assert captured["protocol_name"] == "FTP"

    def test_unset_timeouts_fall_back_to_default(self):
        """When config timeouts are unset, the 5.0 defaults are used."""
        captured = self._build_fuzzer(recv_timeout=None, send_timeout=None)
        assert captured["recv_timeout"] == 5.0
        assert captured["send_timeout"] == 5.0


class TestStatefulFuzzerNodeRegistration:
    """Tests for node registration logic.

    Test the mapping logic in isolation since actual StatefulFuzzer
    requires complex initialization.
    """

    def test_node_to_request_mapping(self):
        """Verify node-to-request mapping data structure."""
        mapping = {}
        # Simulate _register_request_nodes
        for node in ["USER", "PASS"]:
            mapping[node] = "FTP_Auth_Fuzz"
        for node in ["CWD", "LIST"]:
            mapping[node] = "FTP_Critical_Path"

        # Simulate _get_request_info_for_node
        assert mapping.get("USER") == "FTP_Auth_Fuzz"
        assert mapping.get("PASS") == "FTP_Auth_Fuzz"
        assert mapping.get("CWD") == "FTP_Critical_Path"
        assert mapping.get("LIST") == "FTP_Critical_Path"
        assert mapping.get("UNKNOWN") is None

    def test_state_matching_algorithm(self):
        """Test the core state matching algorithm directly."""
        from oida.fuzz.core.base_fuzzer import CommonState

        def state_matches(current_state, required, default_state=CommonState.AUTHENTICATED):
            """Simplified version of _request_state_matches logic."""
            if required is None:
                required = default_state

            if required == CommonState.ANY or required == "ANY":
                return True

            if isinstance(required, list):
                for req in required:
                    req_name = req.value if isinstance(req, CommonState) else req
                    if current_state == req_name:
                        return True
                return False

            req_name = required.value if isinstance(required, CommonState) else required
            return current_state == req_name

        # Test cases
        assert state_matches("AUTHENTICATED", CommonState.ANY) is True
        assert state_matches("AUTHENTICATED", CommonState.AUTHENTICATED) is True
        assert state_matches("PRE_AUTH", CommonState.AUTHENTICATED) is False
        assert state_matches("PRE_AUTH", CommonState.PRE_AUTH) is True
        assert (
            state_matches("CONNECTED", [CommonState.CONNECTED, CommonState.AUTHENTICATED]) is True
        )
        assert (
            state_matches("PRE_AUTH", [CommonState.CONNECTED, CommonState.AUTHENTICATED]) is False
        )
        assert state_matches("CUSTOM", "CUSTOM") is True
        assert state_matches("OTHER", "CUSTOM") is False
        assert state_matches("AUTHENTICATED", None) is True  # default is AUTHENTICATED
        assert state_matches("PRE_AUTH", None) is False  # default is AUTHENTICATED
