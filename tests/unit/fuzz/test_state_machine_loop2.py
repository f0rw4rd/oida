"""Regression tests for state-machine / stateful-fuzzer bug-fix loop 2.

Covers four verified defects:

S5 -- ``StateMachine.traverse_to_state()`` returned True without actually
      performing the transition when the computed path left nothing to walk.
S7 -- ``requires`` boolean combinator: it lists ALTERNATIVE predecessors (OR),
      not a conjunction, and the traversal helpers must agree on that.
S6 -- ``StatefulFuzzer`` tracked connection identity with ``id()``, whose values
      CPython recycles after GC.
C8 -- a ``setup``/``enter`` callback returning ``None`` was treated as failure,
      callbacks of arity 0 and 1 must both work, and ``entry_time`` must be
      refreshed on re-entry.
"""

import gc
import time

import pytest

from src.oida.fuzz.core.session.state_machine import (
    ProtocolState,
    StateMachine,
    StateTransitionError,
    TransitionRule,
    _call_with_optional_context,
)
from src.oida.fuzz.core.stateful_fuzzer import _connection_uid


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


def _linear_machine():
    """A -> B, requires-only machine (no explicit TransitionRules)."""
    a = ProtocolState("A")
    b = ProtocolState("B", requires=["A"])
    return StateMachine(initial_state=a, states=[a, b])


# --------------------------------------------------------------------------
# S5 -- traverse_to_state() must not claim success without transitioning
# --------------------------------------------------------------------------


class TestTraverseToStateHonesty:
    def test_traverse_backwards_to_initial_actually_transitions(self):
        """Walking back to the initial state must really move the machine.

        get_path_to_state("A") returns just ["A"] (the target IS the initial
        state).  The old code could not find the current state "B" in that path,
        defaulted to index 0, sliced off everything and returned True while
        still sitting in B.
        """
        sm = _linear_machine()
        sm.transition_to("B")
        assert sm.current_state.name == "B"

        result = sm.traverse_to_state("A")

        assert sm.current_state.name == "A", (
            "traverse_to_state() left the machine in "
            f"{sm.current_state.name!r} instead of moving it to 'A'"
        )
        assert result is True

    def test_traverse_returns_false_or_raises_when_target_unreachable(self):
        """Never return True when the target cannot actually be reached.

        Rules-based machine: only A -> B is legal, so there is no way back to A.
        The old code returned True (empty remaining slice) while parked in B.
        """
        a = ProtocolState("A")
        b = ProtocolState("B", requires=["A"])
        sm = StateMachine(
            initial_state=a,
            states=[a, b],
            transitions=[TransitionRule("A", "B")],
        )
        sm.transition_to("B")

        with pytest.raises(StateTransitionError):
            sm.traverse_to_state("A")

        assert sm.current_state.name == "B"

    def test_traverse_returns_false_when_a_step_reports_failure(self):
        """A transition step that reports failure must not be reported as success."""

        class FlakyMachine(StateMachine):
            def transition_to(self, state_name, force=False):
                return False  # step declines, without raising

        a = ProtocolState("A")
        b = ProtocolState("B", requires=["A"])
        sm = FlakyMachine(initial_state=a, states=[a, b])

        assert sm.traverse_to_state("B") is False
        assert sm.current_state.name == "A"

    def test_traverse_to_current_state_is_true(self):
        sm = _linear_machine()
        assert sm.traverse_to_state("A") is True
        assert sm.current_state.name == "A"

    def test_traverse_multi_hop_reaches_target(self):
        a = ProtocolState("A")
        b = ProtocolState("B", requires=["A"])
        c = ProtocolState("C", requires=["B"])
        sm = StateMachine(initial_state=a, states=[a, b, c])

        assert sm.traverse_to_state("C") is True
        assert sm.current_state.name == "C"
        assert sm.get_state_history() == ["A", "B", "C"]


# --------------------------------------------------------------------------
# S7 -- `requires` is OR (alternative predecessors), consistently
# --------------------------------------------------------------------------


class TestRequiresIsOrSemantics:
    """`requires=[X, Y]` means "enterable from X OR from Y".

    AND would be unsatisfiable: a machine occupies exactly one state at a time,
    so a multi-entry `requires` read as a conjunction would make the state
    permanently unreachable.  Real machines rely on the OR reading (TCP's
    ESTABLISHED requires ["SYN_SENT", "SYN_RECEIVED"]).
    """

    @staticmethod
    def _tcp_like():
        closed = ProtocolState("CLOSED")
        listen = ProtocolState("LISTEN", requires=["CLOSED"])
        syn_sent = ProtocolState("SYN_SENT", requires=["CLOSED"])
        syn_recv = ProtocolState("SYN_RECEIVED", requires=["LISTEN", "SYN_SENT"])
        established = ProtocolState("ESTABLISHED", requires=["SYN_SENT", "SYN_RECEIVED"])
        return StateMachine(
            initial_state=closed,
            states=[closed, listen, syn_sent, syn_recv, established],
        )

    def test_can_transition_accepts_any_listed_predecessor(self):
        sm = self._tcp_like()
        # Both alternatives are individually sufficient -- OR, not AND.
        assert sm.can_transition("SYN_SENT", "ESTABLISHED") is True
        assert sm.can_transition("SYN_RECEIVED", "ESTABLISHED") is True
        # A state not listed at all is still rejected.
        assert sm.can_transition("LISTEN", "ESTABLISHED") is False
        assert sm.can_transition("CLOSED", "ESTABLISHED") is False

    def test_multi_requires_state_is_actually_reachable(self):
        """Under AND semantics this state could never be entered at all."""
        sm = self._tcp_like()
        path = sm.get_path_to_state("ESTABLISHED")
        assert path, "ESTABLISHED must be reachable under OR semantics"
        assert path[0] == "CLOSED"
        assert path[-1] == "ESTABLISHED"

        assert sm.traverse_to_state("ESTABLISHED") is True
        assert sm.current_state.name == "ESTABLISHED"

    def test_traversal_and_guard_agree_on_every_path_edge(self):
        """Every edge the path finder emits must pass the transition guard."""
        sm = self._tcp_like()
        for target in ("LISTEN", "SYN_SENT", "SYN_RECEIVED", "ESTABLISHED"):
            path = sm.get_path_to_state(target)
            assert path, f"no path to {target}"
            for src, dst in zip(path, path[1:]):
                assert sm.can_transition(src, dst), (
                    f"path {path} contains edge {src} -> {dst} that can_transition() rejects"
                )

    def test_reachability_order_tolerates_cyclic_requires_graph(self):
        """HTTP-style request/response loops are legal under OR semantics.

        get_topological_order() intentionally treats every `requires` entry as a
        dependency edge and raises on cycles (that is its cycle-detection job).
        get_reachability_order() is the OR-aware counterpart used for traversal
        and must list every state without raising.
        """
        disconnected = ProtocolState("DISCONNECTED")
        connected = ProtocolState("CONNECTED", requires=["DISCONNECTED", "RESPONSE_RECEIVED"])
        request_sent = ProtocolState("REQUEST_SENT", requires=["CONNECTED", "PERSISTENT"])
        response = ProtocolState("RESPONSE_RECEIVED", requires=["REQUEST_SENT"])
        persistent = ProtocolState("PERSISTENT", requires=["RESPONSE_RECEIVED"])
        sm = StateMachine(
            initial_state=disconnected,
            states=[disconnected, connected, request_sent, response, persistent],
        )

        with pytest.raises(ValueError, match="Circular dependency"):
            sm.get_topological_order()

        order = sm.get_reachability_order()
        assert order[0] == "DISCONNECTED"
        assert set(order) == set(sm.states)
        assert len(order) == len(set(order)), "reachability order must not repeat states"
        # Every state is preceded by at least one legal predecessor.
        for idx, name in enumerate(order[1:], start=1):
            assert any(sm.can_transition(prev, name) for prev in order[:idx]), (
                f"{name} has no legal predecessor among {order[:idx]}"
            )


# --------------------------------------------------------------------------
# S6 -- stable connection identity instead of id()
# --------------------------------------------------------------------------


class _FakeConn:
    """Stand-in for a fuzzer connection object."""


class TestConnectionIdentity:
    def test_uid_is_stable_across_calls(self):
        conn = _FakeConn()
        first = _connection_uid(conn)
        second = _connection_uid(conn)
        assert first == second
        assert first is not None  # stamped identity, never None for a live conn
        # Verify independently of the memoized return value: the uid must
        # actually be stamped onto the object as an attribute (not just
        # recomputed identically by chance), so reading it directly off the
        # object matches what both calls returned.
        assert getattr(conn, "_oida_conn_uid") == first
        assert getattr(conn, "_oida_conn_uid") == second

    def test_distinct_live_connections_never_collide(self):
        conns = [_FakeConn() for _ in range(200)]
        uids = [_connection_uid(c) for c in conns]
        assert len(set(uids)) == len(uids), "distinct live connections shared a uid"

    def test_uid_not_reused_after_collection(self):
        """The core of S6: id() recycles, the uid must not.

        Create a connection, record its identity, drop it, then create a new
        one.  CPython very often hands the new object the freed address, so the
        id()-based key would compare equal and the fuzzer would treat a brand
        new, unauthenticated socket as the already-authenticated one.
        """
        first = _FakeConn()
        first_id = id(first)
        first_uid = _connection_uid(first)

        del first
        gc.collect()

        second = _FakeConn()
        second_uid = _connection_uid(second)

        assert second_uid != first_uid, "uid was recycled after the previous object died"
        if id(second) == first_id:
            # Address really was recycled -- exactly the case the old key got wrong.
            assert second_uid != first_uid

    def test_uid_falls_back_for_objects_rejecting_attributes(self):
        class Slotted:
            __slots__ = ()

        obj = Slotted()
        uid = _connection_uid(obj)
        assert uid == ("id", id(obj))
        assert _connection_uid(obj) == uid

    def test_uid_of_none_is_none(self):
        assert _connection_uid(None) is None


# --------------------------------------------------------------------------
# C8 -- None means success; arity 0/1 callbacks; entry_time refresh
# --------------------------------------------------------------------------


class TestSetupReturnConvention:
    def test_setup_returning_none_is_success(self):
        calls = []

        def setup():
            calls.append(1)  # returns None

        state = ProtocolState("B", setup=setup, requires=["A"])
        assert state.enter() is True
        assert calls == [1]

    def test_setup_returning_none_allows_transition(self):
        a = ProtocolState("A")
        b = ProtocolState("B", setup=lambda: None, requires=["A"])
        sm = StateMachine(initial_state=a, states=[a, b])

        assert sm.transition_to("B") is True
        assert sm.current_state.name == "B"

    def test_explicit_false_is_still_failure(self):
        state = ProtocolState("B", setup=lambda: False, requires=["A"])
        assert state.enter() is False

        a = ProtocolState("A")
        sm = StateMachine(initial_state=a, states=[a, state])
        with pytest.raises(StateTransitionError):
            sm.transition_to("B")
        assert sm.current_state.name == "A"

    @pytest.mark.parametrize("value", [0, "", [], None, True, "ok", 42])
    def test_only_false_fails(self, value):
        state = ProtocolState("S", setup=lambda: value)
        assert state.enter() is (value is not False)

    def test_zero_is_not_failure(self):
        """A setup callback returning 0 (e.g. a status code) is not a failure."""
        state = ProtocolState("S", setup=lambda: 0)
        assert state.enter() is True

    def test_enter_returns_real_bool(self):
        state = ProtocolState("S", setup=lambda: "truthy string")
        assert state.enter() is True


class TestCallbackArity:
    def test_zero_arg_callback_with_context(self):
        sentinel = object()
        assert _call_with_optional_context(lambda: "no-args", sentinel) == "no-args"

    def test_one_arg_callback_receives_context(self):
        sentinel = object()
        assert _call_with_optional_context(lambda ctx: ctx, sentinel) is sentinel

    def test_one_arg_callback_without_context(self):
        assert _call_with_optional_context(lambda ctx=None: ctx) is None

    def test_none_callback(self):
        assert _call_with_optional_context(None, object()) is None

    def test_state_setup_of_both_arities_enters_cleanly(self):
        seen = []

        class Ctx:
            pass

        ctx = Ctx()
        zero = ProtocolState("ZERO", setup=lambda: seen.append("zero"))
        one = ProtocolState("ONE", setup=lambda c: seen.append(c))

        assert zero.enter(ctx) is True
        assert one.enter(ctx) is True
        assert seen == ["zero", ctx]

    def test_typeerror_inside_callback_is_not_swallowed(self):
        def bad(ctx):
            raise TypeError("boom from inside")

        state = ProtocolState("BAD", setup=bad)
        with pytest.raises(TypeError, match="boom from inside"):
            state.enter(object())


class TestEntryTimeRefresh:
    def test_entry_time_set_when_setup_returns_none(self):
        state = ProtocolState("S", setup=lambda: None)
        assert state.entry_time is None
        assert state.enter() is True
        assert state.entry_time is not None

    def test_entry_time_refreshed_on_reentry(self):
        state = ProtocolState("S", setup=lambda: None, timeout=0.05)
        assert state.enter() is True
        first = state.entry_time

        time.sleep(0.06)
        assert state.is_timed_out() is True

        assert state.enter() is True
        assert state.entry_time > first, "entry_time was not refreshed on re-entry"
        assert state.is_timed_out() is False

    def test_entry_time_not_updated_on_failed_entry(self):
        results = [False, None]
        state = ProtocolState("S", setup=lambda: results.pop(0))

        assert state.enter() is False
        assert state.entry_time is None

        assert state.enter() is True
        assert state.entry_time is not None

    def test_reset_refreshes_initial_state_entry_time(self):
        a = ProtocolState("A", timeout=0.05)
        b = ProtocolState("B", requires=["A"])
        sm = StateMachine(initial_state=a, states=[a, b])

        a.entry_time = time.time() - 10.0
        assert a.is_timed_out() is True

        sm.reset()
        assert a.is_timed_out() is False, "reset() left a stale entry_time on the initial state"

        a.entry_time = time.time() - 10.0
        sm.reset_to_initial()
        assert a.is_timed_out() is False, (
            "reset_to_initial() left a stale entry_time on the initial state"
        )
