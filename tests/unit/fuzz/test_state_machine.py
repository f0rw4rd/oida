"""
Tests for the Protocol State Machine Framework.

Tests cover:
- ProtocolState: State definition with setup/validation callbacks
- TransitionRule: Transition conditions and actions
- StateMachine: State transitions, validation, and attack mode
- create_auth_state_machine factory function
"""

import pytest
import time
from unittest.mock import Mock


# =============================================================================
# Test StateType Enum
# =============================================================================


class TestStateType:
    """Tests for StateType enumeration."""

    def test_state_types_exist(self):
        """All expected state types are defined."""
        from oida.fuzz.core.session.state_machine import StateType

        assert StateType.CONNECTION
        assert StateType.AUTHENTICATION
        assert StateType.TRANSACTION
        assert StateType.SESSION
        assert StateType.DATA_TRANSFER
        assert StateType.ERROR

    def test_state_types_unique(self):
        """State type values are unique."""
        from oida.fuzz.core.session.state_machine import StateType

        values = [st.value for st in StateType]
        assert len(values) == len(set(values))


# =============================================================================
# Test TransitionRule
# =============================================================================


class TestTransitionRuleCreation:
    """Tests for TransitionRule instantiation."""

    def test_basic_creation(self):
        """TransitionRule can be created with basic parameters."""
        from oida.fuzz.core.session.state_machine import TransitionRule

        rule = TransitionRule("STATE_A", "STATE_B")
        assert rule.from_state == "STATE_A"
        assert rule.to_state == "STATE_B"

    def test_creation_with_condition(self):
        """TransitionRule accepts condition callback."""
        from oida.fuzz.core.session.state_machine import TransitionRule

        condition = Mock(return_value=True)
        rule = TransitionRule("A", "B", condition=condition)
        assert rule.condition is condition

    def test_creation_with_action(self):
        """TransitionRule accepts action callback."""
        from oida.fuzz.core.session.state_machine import TransitionRule

        action = Mock()
        rule = TransitionRule("A", "B", action=action)
        assert rule.action is action

    def test_creation_with_description(self):
        """TransitionRule accepts description."""
        from oida.fuzz.core.session.state_machine import TransitionRule

        rule = TransitionRule("A", "B", description="Test transition")
        assert rule.description == "Test transition"


class TestTransitionRuleCanTransition:
    """Tests for TransitionRule.can_transition()."""

    def test_can_transition_no_condition(self):
        """Without condition, can_transition returns True."""
        from oida.fuzz.core.session.state_machine import TransitionRule

        rule = TransitionRule("A", "B")
        assert rule.can_transition() is True

    def test_can_transition_condition_true(self):
        """Returns True when condition returns True."""
        from oida.fuzz.core.session.state_machine import TransitionRule

        condition = Mock(return_value=True)
        rule = TransitionRule("A", "B", condition=condition)
        assert rule.can_transition() is True
        condition.assert_called_once()

    def test_can_transition_condition_false(self):
        """Returns False when condition returns False."""
        from oida.fuzz.core.session.state_machine import TransitionRule

        condition = Mock(return_value=False)
        rule = TransitionRule("A", "B", condition=condition)
        assert rule.can_transition() is False

    def test_can_transition_condition_exception(self):
        """Returns False when condition raises exception."""
        from oida.fuzz.core.session.state_machine import TransitionRule

        condition = Mock(side_effect=RuntimeError("test error"))
        rule = TransitionRule("A", "B", condition=condition)
        assert rule.can_transition() is False


class TestTransitionRuleExecuteAction:
    """Tests for TransitionRule.execute_action()."""

    def test_execute_action_no_action(self):
        """Without action, execute_action does nothing."""
        from oida.fuzz.core.session.state_machine import TransitionRule

        rule = TransitionRule("A", "B")
        rule.execute_action()  # Should not raise

    def test_execute_action_calls_callback(self):
        """Action callback is called."""
        from oida.fuzz.core.session.state_machine import TransitionRule

        action = Mock()
        rule = TransitionRule("A", "B", action=action)
        rule.execute_action()
        action.assert_called_once()

    def test_execute_action_propagates_exception(self):
        """Action exceptions are propagated."""
        from oida.fuzz.core.session.state_machine import TransitionRule

        action = Mock(side_effect=RuntimeError("action failed"))
        rule = TransitionRule("A", "B", action=action)
        with pytest.raises(RuntimeError):
            rule.execute_action()


class TestTransitionRuleRepr:
    """Tests for TransitionRule string representation."""

    def test_repr(self):
        """Repr shows from and to states."""
        from oida.fuzz.core.session.state_machine import TransitionRule

        rule = TransitionRule("CONNECTED", "AUTHENTICATED")
        assert "CONNECTED" in repr(rule)
        assert "AUTHENTICATED" in repr(rule)


# =============================================================================
# Test ProtocolState
# =============================================================================


class TestProtocolStateCreation:
    """Tests for ProtocolState instantiation."""

    def test_basic_creation(self):
        """ProtocolState can be created with name only."""
        from oida.fuzz.core.session.state_machine import ProtocolState

        state = ProtocolState("TEST_STATE")
        assert state.name == "TEST_STATE"

    def test_creation_with_callbacks(self):
        """ProtocolState accepts setup and validation callbacks."""
        from oida.fuzz.core.session.state_machine import ProtocolState

        setup = Mock(return_value=True)
        validation = Mock(return_value=True)
        state = ProtocolState("TEST", setup=setup, validation=validation)
        assert state.setup is setup
        assert state.validation is validation

    def test_creation_with_requires(self):
        """ProtocolState accepts requires list."""
        from oida.fuzz.core.session.state_machine import ProtocolState

        state = ProtocolState("TEST", requires=["CONNECTED", "READY"])
        assert state.requires == ["CONNECTED", "READY"]

    def test_creation_with_state_type(self):
        """ProtocolState accepts state type."""
        from oida.fuzz.core.session.state_machine import ProtocolState, StateType

        state = ProtocolState("TEST", state_type=StateType.AUTHENTICATION)
        assert state.state_type == StateType.AUTHENTICATION

    def test_creation_with_timeout(self):
        """ProtocolState accepts timeout."""
        from oida.fuzz.core.session.state_machine import ProtocolState

        state = ProtocolState("TEST", timeout=5.0)
        assert state.timeout == 5.0


class TestProtocolStateEnter:
    """Tests for ProtocolState.enter()."""

    def test_enter_no_setup(self):
        """Without setup, enter returns True."""
        from oida.fuzz.core.session.state_machine import ProtocolState

        state = ProtocolState("TEST")
        assert state.enter() is True

    def test_enter_setup_success(self):
        """With setup returning True, enter returns True."""
        from oida.fuzz.core.session.state_machine import ProtocolState

        setup = Mock(return_value=True)
        state = ProtocolState("TEST", setup=setup)
        assert state.enter() is True
        setup.assert_called_once()

    def test_enter_setup_failure(self):
        """With setup returning False, enter returns False."""
        from oida.fuzz.core.session.state_machine import ProtocolState

        setup = Mock(return_value=False)
        state = ProtocolState("TEST", setup=setup)
        assert state.enter() is False

    def test_enter_setup_exception(self):
        """Setup exception is propagated."""
        from oida.fuzz.core.session.state_machine import ProtocolState

        setup = Mock(side_effect=RuntimeError("setup failed"))
        state = ProtocolState("TEST", setup=setup)
        with pytest.raises(RuntimeError):
            state.enter()

    def test_enter_records_entry_time(self):
        """Enter records entry time."""
        from oida.fuzz.core.session.state_machine import ProtocolState

        state = ProtocolState("TEST")
        assert state.entry_time is None
        state.enter()
        assert state.entry_time is not None


class TestProtocolStateValidate:
    """Tests for ProtocolState.validate()."""

    def test_validate_no_callback(self):
        """Without validation callback, validate returns True."""
        from oida.fuzz.core.session.state_machine import ProtocolState

        state = ProtocolState("TEST")
        assert state.validate() is True

    def test_validate_success(self):
        """With callback returning True, validate returns True."""
        from oida.fuzz.core.session.state_machine import ProtocolState

        validation = Mock(return_value=True)
        state = ProtocolState("TEST", validation=validation)
        assert state.validate() is True

    def test_validate_failure(self):
        """With callback returning False, validate returns False."""
        from oida.fuzz.core.session.state_machine import ProtocolState

        validation = Mock(return_value=False)
        state = ProtocolState("TEST", validation=validation)
        assert state.validate() is False

    def test_validate_exception(self):
        """Validation exception returns False."""
        from oida.fuzz.core.session.state_machine import ProtocolState

        validation = Mock(side_effect=RuntimeError())
        state = ProtocolState("TEST", validation=validation)
        assert state.validate() is False


class TestProtocolStateTimeout:
    """Tests for ProtocolState timeout handling."""

    def test_is_timed_out_no_timeout(self):
        """Without timeout, is_timed_out returns False."""
        from oida.fuzz.core.session.state_machine import ProtocolState

        state = ProtocolState("TEST")
        state.enter()
        assert state.is_timed_out() is False

    def test_is_timed_out_not_entered(self):
        """Before enter, is_timed_out returns False."""
        from oida.fuzz.core.session.state_machine import ProtocolState

        state = ProtocolState("TEST", timeout=0.001)
        assert state.is_timed_out() is False

    def test_is_timed_out_after_timeout(self):
        """After timeout duration, is_timed_out returns True."""
        from oida.fuzz.core.session.state_machine import ProtocolState

        state = ProtocolState("TEST", timeout=0.01)
        state.enter()
        time.sleep(0.02)
        assert state.is_timed_out() is True

    def test_is_timed_out_before_timeout(self):
        """Before timeout duration, is_timed_out returns False."""
        from oida.fuzz.core.session.state_machine import ProtocolState

        state = ProtocolState("TEST", timeout=10.0)
        state.enter()
        assert state.is_timed_out() is False

    def test_get_time_in_state(self):
        """get_time_in_state returns elapsed time."""
        from oida.fuzz.core.session.state_machine import ProtocolState

        state = ProtocolState("TEST")
        state.enter()
        time.sleep(0.01)
        elapsed = state.get_time_in_state()
        assert elapsed is not None
        assert elapsed >= 0.01

    def test_handle_timeout_calls_callback(self):
        """handle_timeout calls timeout_callback."""
        from oida.fuzz.core.session.state_machine import ProtocolState

        callback = Mock()
        state = ProtocolState("TEST", timeout=0.01, timeout_callback=callback)
        state.handle_timeout()
        callback.assert_called_once()


class TestProtocolStateRepr:
    """Tests for ProtocolState string representation."""

    def test_repr_basic(self):
        """Repr shows state name."""
        from oida.fuzz.core.session.state_machine import ProtocolState

        state = ProtocolState("MY_STATE")
        assert "MY_STATE" in repr(state)

    def test_repr_with_type(self):
        """Repr shows state type if set."""
        from oida.fuzz.core.session.state_machine import ProtocolState, StateType

        state = ProtocolState("TEST", state_type=StateType.CONNECTION)
        assert "CONNECTION" in repr(state)

    def test_repr_with_timeout(self):
        """Repr shows timeout if set."""
        from oida.fuzz.core.session.state_machine import ProtocolState

        state = ProtocolState("TEST", timeout=5.0)
        assert "5.0" in repr(state)


# =============================================================================
# Test StateMachine
# =============================================================================


class TestStateMachineCreation:
    """Tests for StateMachine instantiation."""

    def test_basic_creation(self):
        """StateMachine can be created."""
        from oida.fuzz.core.session.state_machine import StateMachine, ProtocolState

        initial = ProtocolState("INITIAL")
        sm = StateMachine(initial_state=initial, states=[initial])
        assert sm.current_state.name == "INITIAL"

    def test_creation_with_multiple_states(self):
        """StateMachine tracks multiple states."""
        from oida.fuzz.core.session.state_machine import StateMachine, ProtocolState

        s1 = ProtocolState("STATE_1")
        s2 = ProtocolState("STATE_2")
        s3 = ProtocolState("STATE_3")
        sm = StateMachine(initial_state=s1, states=[s1, s2, s3])
        assert len(sm.states) == 3

    def test_creation_with_transitions(self):
        """StateMachine accepts transition rules."""
        from oida.fuzz.core.session.state_machine import (
            StateMachine,
            ProtocolState,
            TransitionRule,
        )

        s1 = ProtocolState("A")
        s2 = ProtocolState("B")
        rule = TransitionRule("A", "B")
        sm = StateMachine(initial_state=s1, states=[s1, s2], transitions=[rule])
        assert len(sm.transitions) == 1

    def test_initial_state_history(self):
        """State history starts with initial state."""
        from oida.fuzz.core.session.state_machine import StateMachine, ProtocolState

        initial = ProtocolState("INITIAL")
        sm = StateMachine(initial_state=initial, states=[initial])
        assert sm.get_state_history() == ["INITIAL"]


class TestStateMachineCanTransition:
    """Tests for StateMachine.can_transition()."""

    def test_can_transition_unknown_state(self):
        """Returns False for unknown target state."""
        from oida.fuzz.core.session.state_machine import StateMachine, ProtocolState

        s1 = ProtocolState("A")
        sm = StateMachine(initial_state=s1, states=[s1])
        assert sm.can_transition("A", "UNKNOWN") is False

    def test_can_transition_with_rule(self):
        """Checks transition rule condition."""
        from oida.fuzz.core.session.state_machine import (
            StateMachine,
            ProtocolState,
            TransitionRule,
        )

        s1 = ProtocolState("A")
        s2 = ProtocolState("B")
        condition = Mock(return_value=True)
        rule = TransitionRule("A", "B", condition=condition)
        sm = StateMachine(initial_state=s1, states=[s1, s2], transitions=[rule])
        assert sm.can_transition("A", "B") is True

    def test_can_transition_with_requires(self):
        """Uses requires field when no rule exists."""
        from oida.fuzz.core.session.state_machine import StateMachine, ProtocolState

        s1 = ProtocolState("A")
        s2 = ProtocolState("B", requires=["A"])
        sm = StateMachine(initial_state=s1, states=[s1, s2])
        assert sm.can_transition("A", "B") is True
        assert sm.can_transition("X", "B") is False

    def test_can_transition_no_restrictions(self):
        """Returns True when no rules or requires."""
        from oida.fuzz.core.session.state_machine import StateMachine, ProtocolState

        s1 = ProtocolState("A")
        s2 = ProtocolState("B")
        sm = StateMachine(initial_state=s1, states=[s1, s2])
        assert sm.can_transition("A", "B") is True


class TestStateMachineTransitionTo:
    """Tests for StateMachine.transition_to()."""

    def test_transition_to_success(self):
        """Successful transition updates current state."""
        from oida.fuzz.core.session.state_machine import StateMachine, ProtocolState

        s1 = ProtocolState("A")
        s2 = ProtocolState("B", requires=["A"])
        sm = StateMachine(initial_state=s1, states=[s1, s2])
        sm.transition_to("B")
        assert sm.current_state.name == "B"

    def test_transition_to_unknown_state_raises(self):
        """Transition to unknown state raises."""
        from oida.fuzz.core.session.state_machine import (
            StateMachine,
            ProtocolState,
            StateTransitionError,
        )

        s1 = ProtocolState("A")
        sm = StateMachine(initial_state=s1, states=[s1])
        with pytest.raises(StateTransitionError):
            sm.transition_to("UNKNOWN")

    def test_transition_to_invalid_raises(self):
        """Invalid transition raises error."""
        from oida.fuzz.core.session.state_machine import (
            StateMachine,
            ProtocolState,
            StateTransitionError,
        )

        s1 = ProtocolState("A")
        s2 = ProtocolState("B", requires=["C"])  # Requires C, not A
        sm = StateMachine(initial_state=s1, states=[s1, s2])
        with pytest.raises(StateTransitionError):
            sm.transition_to("B")

    def test_transition_to_with_force(self):
        """Force bypasses validation."""
        from oida.fuzz.core.session.state_machine import StateMachine, ProtocolState

        s1 = ProtocolState("A")
        s2 = ProtocolState("B", requires=["C"])  # Invalid normally
        sm = StateMachine(initial_state=s1, states=[s1, s2])
        sm.transition_to("B", force=True)
        assert sm.current_state.name == "B"

    def test_transition_to_updates_history(self):
        """Transition updates state history."""
        from oida.fuzz.core.session.state_machine import StateMachine, ProtocolState

        s1 = ProtocolState("A")
        s2 = ProtocolState("B", requires=["A"])
        sm = StateMachine(initial_state=s1, states=[s1, s2])
        sm.transition_to("B")
        assert sm.get_state_history() == ["A", "B"]

    def test_transition_executes_rule_action(self):
        """Transition executes rule action."""
        from oida.fuzz.core.session.state_machine import (
            StateMachine,
            ProtocolState,
            TransitionRule,
        )

        s1 = ProtocolState("A")
        s2 = ProtocolState("B")
        action = Mock()
        rule = TransitionRule("A", "B", action=action)
        sm = StateMachine(initial_state=s1, states=[s1, s2], transitions=[rule])
        sm.transition_to("B")
        action.assert_called_once()

    def test_transition_setup_failure_raises(self):
        """Setup failure raises error."""
        from oida.fuzz.core.session.state_machine import (
            StateMachine,
            ProtocolState,
            StateTransitionError,
        )

        s1 = ProtocolState("A")
        s2 = ProtocolState("B", setup=Mock(return_value=False))
        sm = StateMachine(initial_state=s1, states=[s1, s2])
        with pytest.raises(StateTransitionError):
            sm.transition_to("B")


class TestStateMachineValidation:
    """Tests for StateMachine validation features."""

    def test_validate_current_state(self):
        """validate_current_state calls state validation."""
        from oida.fuzz.core.session.state_machine import StateMachine, ProtocolState

        validation = Mock(return_value=True)
        s1 = ProtocolState("A", validation=validation)
        sm = StateMachine(initial_state=s1, states=[s1])
        assert sm.validate_current_state() is True
        validation.assert_called_once()

    def test_require_state_already_in(self):
        """require_state validates if already in state."""
        from oida.fuzz.core.session.state_machine import StateMachine, ProtocolState

        validation = Mock(return_value=True)
        s1 = ProtocolState("A", validation=validation)
        sm = StateMachine(initial_state=s1, states=[s1])
        sm.require_state("A")
        validation.assert_called()

    def test_require_state_transitions(self):
        """require_state transitions if not in state."""
        from oida.fuzz.core.session.state_machine import StateMachine, ProtocolState

        s1 = ProtocolState("A")
        s2 = ProtocolState("B", requires=["A"])
        sm = StateMachine(initial_state=s1, states=[s1, s2])
        sm.require_state("B")
        assert sm.current_state.name == "B"


class TestStateMachineAttackMode:
    """Tests for StateMachine attack mode (invalid transitions)."""

    def test_allow_invalid_transitions_flag(self):
        """allow_invalid_transitions bypasses validation."""
        from oida.fuzz.core.session.state_machine import StateMachine, ProtocolState

        s1 = ProtocolState("A")
        s2 = ProtocolState("B", requires=["C"])  # Invalid from A
        sm = StateMachine(initial_state=s1, states=[s1, s2], allow_invalid_transitions=True)
        sm.transition_to("B")  # Should not raise
        assert sm.current_state.name == "B"

    def test_enable_invalid_state_testing(self):
        """enable_invalid_state_testing sets flag."""
        from oida.fuzz.core.session.state_machine import StateMachine, ProtocolState

        s1 = ProtocolState("A")
        sm = StateMachine(initial_state=s1, states=[s1])
        sm.enable_invalid_state_testing()
        assert sm.allow_invalid_transitions is True

    def test_disable_invalid_state_testing(self):
        """disable_invalid_state_testing clears flag."""
        from oida.fuzz.core.session.state_machine import StateMachine, ProtocolState

        s1 = ProtocolState("A")
        sm = StateMachine(initial_state=s1, states=[s1], allow_invalid_transitions=True)
        sm.disable_invalid_state_testing()
        assert sm.allow_invalid_transitions is False


class TestStateMachineHistory:
    """Tests for StateMachine history and logging."""

    def test_get_state_history(self):
        """get_state_history returns copy of history."""
        from oida.fuzz.core.session.state_machine import StateMachine, ProtocolState

        s1 = ProtocolState("A")
        s2 = ProtocolState("B", requires=["A"])
        sm = StateMachine(initial_state=s1, states=[s1, s2])
        sm.transition_to("B")
        history = sm.get_state_history()
        assert history == ["A", "B"]
        # Modifying returned list doesn't affect internal
        history.append("C")
        assert sm.get_state_history() == ["A", "B"]

    def test_get_transition_log(self):
        """get_transition_log returns detailed log."""
        from oida.fuzz.core.session.state_machine import StateMachine, ProtocolState

        s1 = ProtocolState("A")
        s2 = ProtocolState("B", requires=["A"])
        sm = StateMachine(initial_state=s1, states=[s1, s2])
        sm.transition_to("B")
        log = sm.get_transition_log()
        assert len(log) == 1
        assert log[0]["from"] == "A"
        assert log[0]["to"] == "B"
        assert "timestamp" in log[0]

    def test_reset_to_initial(self):
        """reset_to_initial returns to initial state."""
        from oida.fuzz.core.session.state_machine import StateMachine, ProtocolState

        s1 = ProtocolState("A")
        s2 = ProtocolState("B", requires=["A"])
        sm = StateMachine(initial_state=s1, states=[s1, s2])
        sm.transition_to("B")
        sm.reset_to_initial()
        assert sm.current_state.name == "A"
        assert sm.get_state_history() == ["A"]


class TestStateMachineTransitionGraph:
    """Tests for StateMachine transition graph."""

    def test_get_transition_graph(self):
        """get_transition_graph returns valid transitions."""
        from oida.fuzz.core.session.state_machine import StateMachine, ProtocolState

        s1 = ProtocolState("A")
        s2 = ProtocolState("B", requires=["A"])
        s3 = ProtocolState("C", requires=["B"])
        sm = StateMachine(initial_state=s1, states=[s1, s2, s3])
        graph = sm.get_transition_graph()
        assert "B" in graph["A"]
        assert "C" in graph["B"]

    def test_get_valid_next_states(self):
        """get_valid_next_states returns reachable states."""
        from oida.fuzz.core.session.state_machine import StateMachine, ProtocolState

        s1 = ProtocolState("A")
        s2 = ProtocolState("B", requires=["A"])
        s3 = ProtocolState("C", requires=["A"])
        sm = StateMachine(initial_state=s1, states=[s1, s2, s3])
        next_states = sm.get_valid_next_states()
        assert "B" in next_states
        assert "C" in next_states


# =============================================================================
# Test Factory Functions
# =============================================================================


class TestCreateAuthStateMachine:
    """Tests for create_auth_state_machine factory."""

    def test_creates_two_states(self):
        """Factory creates CONNECTED and AUTHENTICATED states."""
        from oida.fuzz.core.session.state_machine import create_auth_state_machine

        login = Mock(return_value=True)
        sm = create_auth_state_machine(login_callback=login)
        assert "CONNECTED" in sm.states
        assert "AUTHENTICATED" in sm.states

    def test_initial_state_is_connected(self):
        """Initial state is CONNECTED."""
        from oida.fuzz.core.session.state_machine import create_auth_state_machine

        login = Mock(return_value=True)
        sm = create_auth_state_machine(login_callback=login)
        assert sm.current_state.name == "CONNECTED"

    def test_login_required_for_authenticated(self):
        """Login callback is used for AUTHENTICATED state."""
        from oida.fuzz.core.session.state_machine import create_auth_state_machine

        login = Mock(return_value=True)
        sm = create_auth_state_machine(login_callback=login)
        sm.transition_to("AUTHENTICATED")
        login.assert_called_once()


class TestStateMachineRegressions:
    """Regression tests for state machine correctness fixes."""

    def _two_state_cycle(self):
        from oida.fuzz.core.session.state_machine import (
            ProtocolState,
            StateMachine,
            TransitionRule,
        )

        s1 = ProtocolState(name="S1")
        s2 = ProtocolState(name="S2")
        rules = [
            TransitionRule(from_state="S1", to_state="S2"),
            TransitionRule(from_state="S2", to_state="S1"),
        ]
        return StateMachine(initial_state=s1, states=[s1, s2], transitions=rules)

    def test_reset_returns_to_initial_after_history_eviction(self):
        """reset()/reset_to_initial() must use the true initial state even after
        the bounded state_history deque (maxlen=1000) has evicted it."""
        sm = self._two_state_cycle()
        # More than 1000 transitions so the original initial entry is evicted.
        for _ in range(1100):
            target = "S2" if sm.current_state.name == "S1" else "S1"
            sm.transition_to(target)

        # The deque no longer starts with the initial state...
        assert sm.get_state_history()[0] != "S1"

        # ...but reset must still land on it.
        sm.reset_to_initial()
        assert sm.current_state.name == "S1"

        sm.transition_to("S2")
        sm.reset()
        assert sm.current_state.name == "S1"

    def test_get_path_is_rules_traversable(self):
        """get_path_to_state must respect the rule table (not just 'requires'),
        and traverse_to_state must follow the path without raising."""
        from oida.fuzz.core.session.state_machine import (
            ProtocolState,
            StateMachine,
            TransitionRule,
        )

        a = ProtocolState(name="A")
        b = ProtocolState(name="B")
        c = ProtocolState(name="C")
        # 'requires' is empty on C, so the old BFS treated C as reachable from
        # anywhere (A->C). The rule table only permits A->B->C, so the returned
        # path must go through B.
        rules = [
            TransitionRule(from_state="A", to_state="B"),
            TransitionRule(from_state="B", to_state="C"),
        ]
        sm = StateMachine(initial_state=a, states=[a, b, c], transitions=rules)

        assert sm.get_path_to_state("C") == ["A", "B", "C"]
        assert sm.traverse_to_state("C") is True
        assert sm.current_state.name == "C"

    def test_failed_enter_does_not_exit_current_state(self):
        """A failed enter() must not run the current state's on_exit, and must
        leave the machine in its current state (clean rollback)."""
        from oida.fuzz.core.session.state_machine import (
            ProtocolState,
            StateMachine,
            StateTransitionError,
            TransitionRule,
        )

        exit_calls = []
        s1 = ProtocolState(name="S1", on_exit=lambda: exit_calls.append("S1"))
        s2 = ProtocolState(name="S2", setup=lambda: False)  # entry always fails
        rules = [TransitionRule(from_state="S1", to_state="S2")]
        sm = StateMachine(initial_state=s1, states=[s1, s2], transitions=rules)

        with pytest.raises(StateTransitionError):
            sm.transition_to("S2")

        assert sm.current_state.name == "S1"
        assert exit_calls == []

    def test_set_state_no_setup_records_entry_time(self):
        """set_state_no_setup must stamp entry_time so timeout tracking keeps
        working after a forced (attack-mode) transition."""
        sm = self._two_state_cycle()
        assert sm.states["S2"].entry_time is None
        sm.set_state_no_setup("S2")
        assert sm.states["S2"].entry_time is not None

    def test_context_callback_internal_typeerror_propagates(self):
        """A TypeError raised *inside* a context-accepting callback must
        propagate, not be silently swallowed and retried with no args."""
        from oida.fuzz.core.session.state_machine import _call_with_optional_context

        def cb(_ctx):
            raise TypeError("internal boom")

        with pytest.raises(TypeError, match="internal boom"):
            _call_with_optional_context(cb, context=object())


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
