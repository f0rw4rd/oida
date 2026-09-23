"""Regression tests for three StatefulFuzzer state-handling bugs.

Bug A: a single auth failure aborted the ENTIRE campaign, including requests
       that require no authentication (PRE_AUTH / ANY).
Bug B: the fuzzer re-authenticated on every test case when the state machine
       had no literal "AUTHENTICATED" state (protocol-specific state names).
Bug C: preflight enter() was called without the state-machine context, so
       context-style setup callbacks received None and appeared unreachable.

Each test is written so it FAILS against the pre-fix code and PASSES after.
"""

from unittest.mock import MagicMock

import pytest

from oida.fuzz.core.base_fuzzer import CommonState, RequestInfo
from oida.fuzz.core.stateful_fuzzer import StatefulFuzzer, AuthenticationFailedError
from oida.fuzz.core.session.state_machine import ProtocolState, StateMachine
from oida.fuzz.core.session.state_context import StateContext


class _CountingAuthenticator:
    """Minimal authenticator that records how many times it authenticates."""

    def __init__(self):
        self.calls = 0

    def authenticate(self, conn):
        self.calls += 1
        return True

    def get_credentials(self):
        return {"username": "u"}


class _ConcreteStatefulFuzzer(StatefulFuzzer):
    def _define_protocol(self):  # pragma: no cover - never executed
        pass


def _make_fuzzer(*, state_machine=None, authenticator=None, default_state, auth_failed=False):
    """Build a StatefulFuzzer without running its (session-heavy) __init__."""
    fuzzer = object.__new__(_ConcreteStatefulFuzzer)
    fuzzer.log = MagicMock()
    fuzzer.PROTOCOL_NAME = "test"
    fuzzer.DEFAULT_REQUEST_STATE = default_state
    fuzzer.state_machine = state_machine
    fuzzer.authenticator = authenticator
    fuzzer._auth_failed = auth_failed
    fuzzer._auth_callback_registered = False
    fuzzer._authenticated_conn_id = None
    fuzzer._current_state = CommonState.CONNECTED.value
    fuzzer._available_requests = {}
    fuzzer._node_to_request_map = {}
    return fuzzer


def _wire_pre_send(fuzzer):
    """Register the state-aware callback and return it plus (target, session)."""
    conn = object()  # stable identity, no _connection_generation attr
    target = MagicMock()
    target._target_connection = conn

    session = MagicMock()
    session._callback_monitor.on_pre_send = []
    session.targets = [target]

    fuzzer._session = session
    fuzzer._setup_auth_callback()
    callback = session._callback_monitor.on_pre_send[-1]

    def invoke(request_name):
        session.fuzz_node = MagicMock()
        session.fuzz_node.name = request_name
        return callback(target, MagicMock(), session, MagicMock())

    return invoke


# ---------------------------------------------------------------------------
# Bug A: one auth failure must not abort no-auth (PRE_AUTH / ANY) requests
# ---------------------------------------------------------------------------


class TestBugAAuthFailureScope:
    def test_pre_auth_request_proceeds_after_auth_failure(self):
        fuzzer = _make_fuzzer(default_state=CommonState.AUTHENTICATED, auth_failed=True)
        fuzzer._available_requests = {
            "PRE": RequestInfo("PRE", "", requires_state=CommonState.PRE_AUTH)
        }
        invoke = _wire_pre_send(fuzzer)

        # Must NOT raise even though a prior auth failed.
        invoke("PRE")
        assert fuzzer._current_state == CommonState.PRE_AUTH.value

    def test_any_request_proceeds_after_auth_failure(self):
        fuzzer = _make_fuzzer(default_state=CommonState.AUTHENTICATED, auth_failed=True)
        fuzzer._available_requests = {"ANY": RequestInfo("ANY", "", requires_state=CommonState.ANY)}
        invoke = _wire_pre_send(fuzzer)

        invoke("ANY")  # must not raise
        # ANY requests do not enforce or mutate state; the fuzzer must remain
        # in whatever state it was in before the call (CONNECTED, per
        # _make_fuzzer), not get bumped to PRE_AUTH/AUTHENTICATED.
        assert fuzzer._current_state == CommonState.CONNECTED.value

    def test_authenticated_request_still_aborts_after_auth_failure(self):
        fuzzer = _make_fuzzer(default_state=CommonState.AUTHENTICATED, auth_failed=True)
        fuzzer._available_requests = {
            "AUTH": RequestInfo("AUTH", "", requires_state=CommonState.AUTHENTICATED)
        }
        invoke = _wire_pre_send(fuzzer)

        with pytest.raises(AuthenticationFailedError):
            invoke("AUTH")


# ---------------------------------------------------------------------------
# Bug B: no re-auth per case when SM has no literal "AUTHENTICATED" state
# ---------------------------------------------------------------------------


class TestBugBNoRepeatedAuth:
    def _sm_without_authenticated(self):
        # Protocol-specific names only; no literal "AUTHENTICATED" (like MQTT).
        connected = ProtocolState("CONNECTED")
        ready = ProtocolState("READY", requires=["CONNECTED"])
        return StateMachine(connected, [connected, ready])

    def test_auth_runs_once_across_multiple_cases(self):
        auth = _CountingAuthenticator()
        fuzzer = _make_fuzzer(
            state_machine=self._sm_without_authenticated(),
            authenticator=auth,
            default_state=CommonState.AUTHENTICATED,
        )
        fuzzer._available_requests = {
            "AUTH": RequestInfo("AUTH", "", requires_state=CommonState.AUTHENTICATED)
        }
        invoke = _wire_pre_send(fuzzer)

        # Three test cases on the SAME connection.
        invoke("AUTH")
        invoke("AUTH")
        invoke("AUTH")

        assert auth.calls == 1, f"expected auth once, got {auth.calls} (re-auth per case)"


# ---------------------------------------------------------------------------
# Bug C: preflight must pass the real StateContext into enter()
# ---------------------------------------------------------------------------


class TestBugCPreflightContext:
    def test_context_style_setup_is_reachable(self):
        received = {}

        def open_setup(ctx):
            # Fails with AttributeError if ctx is None (the pre-fix behavior).
            ctx.set("opened", True)
            received["ctx"] = ctx
            return True

        connected = ProtocolState("CONNECTED")
        open_state = ProtocolState("OPEN", setup=open_setup, requires=["CONNECTED"])
        ctx = StateContext()
        sm = StateMachine(connected, [connected, open_state], context=ctx)

        fuzzer = _make_fuzzer(state_machine=sm, default_state=CommonState.ANY)

        all_reachable, results = fuzzer._preflight_state_check()

        open_result = next(r for r in results if r.state_name == "OPEN")
        assert open_result.reachable is True, open_result.error
        assert received["ctx"] is ctx
