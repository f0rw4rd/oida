"""Protocol State Machine Framework for stateful protocol fuzzing."""

from typing import Callable, Optional, List, Dict, Any, TYPE_CHECKING
from enum import Enum, auto
from collections import deque
import threading
import time
import inspect

from ....utils.ics_logger import get_logger

if TYPE_CHECKING:
    from .state_context import StateContext

# Module-level logger for state machine operations
_log = get_logger("STATE", "machine", 0)


def _call_with_optional_context(func: Callable, context: Optional["StateContext"] = None) -> Any:
    """Call a function, passing context if it accepts a positional parameter.

    Inspects the function signature for any positional parameter
    (POSITIONAL_ONLY or POSITIONAL_OR_KEYWORD). If one exists and a
    context is provided, the context is passed as the first argument.
    Falls back to a no-arg call on TypeError or when the signature
    cannot be inspected.

    Args:
        func: Callback function to call
        context: Optional StateContext to pass

    Returns:
        Return value from the callback
    """
    if func is None:
        return None

    if context is not None:
        # Check if function accepts at least one positional parameter
        try:
            sig = inspect.signature(func)
            positional_kinds = (
                inspect.Parameter.POSITIONAL_ONLY,
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
            )
            has_positional = any(p.kind in positional_kinds for p in sig.parameters.values())
        except (ValueError, TypeError):
            # Can't introspect (e.g., a built-in): we genuinely don't know the
            # arity, so best-effort try with context and fall back to no-arg.
            # This is the ONLY place we swallow TypeError — when we can inspect
            # the signature we dispatch to the exact form below and let any
            # TypeError raised *inside* the callback propagate.
            try:
                return func(context)
            except TypeError:
                return func()

        if has_positional:
            return func(context)

    return func()


class StateTransitionError(Exception):
    """Raised when a state transition fails"""


class StateType(Enum):
    """Classification of state types for protocol state machines"""

    CONNECTION = auto()  # Network connection states (CONNECTED, DISCONNECTED)
    AUTHENTICATION = auto()  # Authentication flow states (AUTHENTICATED, etc.)
    TRANSACTION = auto()  # Request/response transaction states
    SESSION = auto()  # Session management states (TLS_ESTABLISHED, etc.)
    DATA_TRANSFER = auto()  # Data transfer states (ACTIVE, PASSIVE for FTP)
    ERROR = auto()  # Error/exception states


class TransitionRule:
    """Defines allowed state transitions with optional conditions and actions.

    Callbacks can optionally accept a StateContext as their first parameter
    for context-aware transitions.
    """

    def __init__(
        self,
        from_state: str,
        to_state: str,
        condition: Optional[Callable[..., bool]] = None,
        action: Optional[Callable[..., None]] = None,
        description: str = "",
    ):
        self.from_state = from_state
        self.to_state = to_state
        self.condition = condition
        self.action = action
        self.description = description

    def can_transition(self, context: Optional["StateContext"] = None) -> bool:
        """Check if transition is allowed based on condition.

        Args:
            context: Optional StateContext for condition evaluation

        Returns:
            True if transition is allowed
        """
        if self.condition is None:
            return True
        try:
            return bool(_call_with_optional_context(self.condition, context))
        except Exception as e:
            _log.fail(f"Transition condition check failed: {e}")
            return False

    def execute_action(self, context: Optional["StateContext"] = None):
        """Execute transition action if defined.

        Args:
            context: Optional StateContext for action execution
        """
        if self.action:
            try:
                _call_with_optional_context(self.action, context)
            except Exception as e:
                _log.fail(f"Transition action failed: {e}")
                raise

    def __repr__(self):
        return f"TransitionRule({self.from_state} → {self.to_state})"


class ProtocolState:
    """Represents a single protocol state (e.g., CONNECTED, AUTHENTICATED).

    Callbacks can optionally accept a StateContext as their first parameter:

    Without context (backward compatible):
        setup=lambda: do_something()

    With context (new style):
        setup=lambda ctx: ctx.set("key", value) or do_something()

    The state machine will automatically detect which style is used and
    pass the context only when the callback accepts it.

    Note on hierarchy: ``parent``/``children`` and the ancestor helpers exist
    as scaffolding, but StateMachine.transition_to() does NOT yet implement
    hierarchical (statechart) semantics — entering/exiting a child does not run
    its ancestors' on_enter/on_exit, and there is no least-common-ancestor
    handling. Setting ``parent=`` today only builds the tree for introspection;
    do not rely on superstate behavior being inherited until that is wired up.

    Note on ``requires``: it lists ALTERNATIVE valid predecessor states (OR, not
    AND). ``requires=["SYN_SENT", "SYN_RECEIVED"]`` means "this state may be
    entered from SYN_SENT *or* from SYN_RECEIVED" — see the TCP and HTTP fuzzer
    state machines. AND semantics would be unsatisfiable: a machine occupies
    exactly one state at a time, so a multi-entry ``requires`` read as a
    conjunction would make the state permanently unreachable.
    StateMachine.can_transition() / get_path_to_state() / get_reachability_order()
    all implement the OR reading.

    Note on ``setup``: the callback signals failure ONLY by returning an explicit
    ``False``. Returning ``None`` — the normal Python convention for "did the
    work, nothing to report" — is success.

    Note on timeouts: ``timeout``/``timeout_callback`` are evaluated lazily —
    is_timed_out() is only checked at the start of the next transition_to().
    There is no background timer, so a timeout callback will not fire on its own
    if no further transition is attempted.
    """

    def __init__(
        self,
        name: str,
        setup: Optional[Callable[..., bool]] = None,
        validation: Optional[Callable[..., bool]] = None,
        requires: Optional[List[str]] = None,
        description: str = "",
        state_type: Optional[StateType] = None,
        timeout: Optional[float] = None,
        timeout_callback: Optional[Callable[..., None]] = None,
        parent: Optional["ProtocolState"] = None,
        on_enter: Optional[Callable[..., None]] = None,
        on_exit: Optional[Callable[..., None]] = None,
    ):
        self.name = name
        self.setup = setup
        self.validation = validation
        self.requires = requires or []
        self.description = description
        self.state_type = state_type
        self.timeout = timeout
        self.timeout_callback = timeout_callback
        self.entry_time: Optional[float] = None
        # Hierarchical state support (Phase 4 preparation)
        self.parent = parent
        self.children: List["ProtocolState"] = []
        self.on_enter = on_enter
        self.on_exit = on_exit

        # Register with parent if provided
        if parent is not None:
            parent.children.append(self)

    def has_setup(self) -> bool:
        """Return True if setup callback is defined."""
        return self.setup is not None

    def is_error_state(self) -> bool:
        """Return True if this is an ERROR type state."""
        return self.state_type == StateType.ERROR

    def enter(self, context: Optional["StateContext"] = None) -> bool:
        """Enter this state by running the setup callback.

        A setup callback signals failure ONLY by returning an explicit ``False``.
        Returning ``None`` -- the normal Python convention for "did the work,
        nothing to report" -- counts as success, as does any other value
        (including falsy ones such as ``0`` or ``""``).

        Args:
            context: Optional StateContext for data propagation

        Returns:
            True if state entry succeeded
        """
        # Run on_enter callback if defined
        if self.on_enter:
            try:
                _call_with_optional_context(self.on_enter, context)
            except Exception as e:
                _log.fail(f"on_enter callback failed for {self.name}: {e}")
                # Don't fail state entry for on_enter errors

        if self.setup:
            _log.debug(f"Entering state: {self.name}")
            try:
                result = _call_with_optional_context(self.setup, context)
                # Only an explicit False means "setup failed"; a callback that
                # returns None (or 0, or "") did its job and reported nothing.
                if result is False:
                    _log.fail(f"Failed to enter state: {self.name}")
                    return False
                _log.debug(f"Successfully entered state: {self.name}")
                # (Re-)record entry time for timeout tracking. This must happen
                # on every successful entry, including re-entry of the state we
                # are already in, or is_timed_out() keeps using a stale stamp.
                self.entry_time = time.time()
                return True
            except Exception as e:
                _log.fail(f"Exception while entering state {self.name}: {e}")
                raise
        # No setup means we can always enter
        self.entry_time = time.time()
        return True

    def exit(self, context: Optional["StateContext"] = None) -> None:
        """Exit this state, running on_exit callback if defined.

        Args:
            context: Optional StateContext for data propagation
        """
        if self.on_exit:
            try:
                _call_with_optional_context(self.on_exit, context)
            except Exception as e:
                _log.fail(f"on_exit callback failed for {self.name}: {e}")

    def validate(self, context: Optional["StateContext"] = None) -> bool:
        """Check if we're still in this state.

        Args:
            context: Optional StateContext for validation checks

        Returns:
            True if state is still valid
        """
        if self.validation:
            try:
                is_valid = _call_with_optional_context(self.validation, context)
                if not is_valid:
                    _log.warning(f"State validation failed: {self.name}")
                return is_valid
            except Exception as e:
                _log.fail(f"Exception during state validation for {self.name}: {e}")
                return False
        return True  # No validation callback = always valid

    def is_timed_out(self) -> bool:
        """Check if this state has exceeded its timeout."""
        if self.timeout is None or self.entry_time is None:
            return False
        elapsed = time.time() - self.entry_time
        return elapsed > self.timeout

    def get_time_in_state(self) -> Optional[float]:
        """Get how long we've been in this state."""
        if self.entry_time is None:
            return None
        return time.time() - self.entry_time

    def handle_timeout(self, context: Optional["StateContext"] = None):
        """Execute timeout callback if defined.

        Args:
            context: Optional StateContext
        """
        if self.timeout_callback:
            _log.warning(f"State {self.name} timed out after {self.timeout} seconds")
            try:
                _call_with_optional_context(self.timeout_callback, context)
            except Exception as e:
                _log.fail(f"Timeout callback failed for {self.name}: {e}")

    def get_ancestors(self) -> List["ProtocolState"]:
        """Get list of ancestor states (parent, grandparent, etc).

        Returns:
            List from immediate parent to root
        """
        ancestors = []
        current = self.parent
        while current is not None:
            ancestors.append(current)
            current = current.parent
        return ancestors

    def is_descendant_of(self, state: "ProtocolState") -> bool:
        """Check if this state is a descendant of another state.

        Args:
            state: Potential ancestor state

        Returns:
            True if state is an ancestor
        """
        return state in self.get_ancestors()

    def __repr__(self):
        type_str = f", type={self.state_type.name}" if self.state_type else ""
        timeout_str = f", timeout={self.timeout}s" if self.timeout else ""
        parent_str = f", parent={self.parent.name}" if self.parent else ""
        return f"ProtocolState(name='{self.name}'{type_str}{timeout_str}{parent_str})"


class StateMachine:
    """Manages protocol states and transitions.

    Supports optional StateContext for response data propagation between
    state transitions. When a context is provided, it is passed to all
    callbacks that accept it (backward compatible with existing callbacks).

    Example:
        # Without context (backward compatible)
        sm = StateMachine(initial_state, states)
        sm.transition_to("AUTHENTICATED")

        # With context (new style)
        ctx = StateContext()
        sm = StateMachine(initial_state, states, context=ctx)
        sm.transition_to("AUTHENTICATED")
        # Callbacks can now access: ctx.get("key"), ctx.set_response("OP", data)
    """

    def __init__(
        self,
        initial_state: ProtocolState,
        states: List[ProtocolState],
        transitions: Optional[List[TransitionRule]] = None,
        allow_invalid_transitions: bool = False,
        context: Optional["StateContext"] = None,
    ):
        self.states: Dict[str, ProtocolState] = {s.name: s for s in states}
        # Ensure the initial state is part of the machine so resets and
        # name lookups stay consistent.
        if initial_state.name not in self.states:
            self.states[initial_state.name] = initial_state
        self.current_state = initial_state
        # Remember the initial state explicitly. It must NOT be recovered from
        # state_history, which is a bounded deque (maxlen below): after enough
        # transitions the left end is evicted and history[0] is no longer the
        # initial state, which would make reset() land on the wrong state.
        self._initial_state = initial_state
        self.transitions = transitions or []
        self.allow_invalid_transitions = allow_invalid_transitions
        self.state_history: deque[str] = deque([initial_state.name], maxlen=1000)
        self.transition_log: deque[Dict[str, Any]] = deque(maxlen=1000)
        self._context = context
        # Re-entrant so that the whole transition (check -> action -> enter ->
        # commit) can be held under one lock without deadlocking if a callback
        # legitimately re-enters the machine on the same thread.
        self._lock = threading.RLock()

        _log.debug(f"StateMachine initialized with {len(states)} states")
        _log.debug(f"Initial state: {initial_state.name}")
        _log.debug(f"Invalid transitions allowed: {allow_invalid_transitions}")
        if context:
            _log.debug("StateContext attached")

    @property
    def initial_state(self) -> "ProtocolState":
        """The authoritative initial state.

        Prefer this over ``state_history[0]``: state_history is a bounded deque
        whose left end is evicted after enough transitions, so history[0] is not
        reliably the initial state.
        """
        return self._initial_state

    @property
    def context(self) -> Optional["StateContext"]:
        """Get the attached StateContext."""
        return self._context

    @context.setter
    def context(self, ctx: Optional["StateContext"]) -> None:
        """Attach or replace StateContext."""
        self._context = ctx
        if ctx:
            _log.debug("StateContext attached to StateMachine")

    def can_transition(self, from_state: str, to_state: str) -> bool:
        """Check if transition is allowed.

        Resolution order:
        1. Explicit TransitionRule for this from->to pair — use its condition
        2. Target state ``requires`` field — check from_state membership.
           ``requires`` lists ALTERNATIVE predecessors (OR, never AND): the
           transition is legal when from_state is ANY one of them. AND would be
           unsatisfiable, since the machine only ever occupies one state at a
           time — a multi-entry ``requires`` read as a conjunction would make
           the target permanently unreachable. Real machines depend on the OR
           reading (TCP: ESTABLISHED requires ["SYN_SENT", "SYN_RECEIVED"]).
           ``get_path_to_state()`` / ``get_reachability_order()`` use this same
           predicate, so guard and traversal cannot disagree.
        3. If any TransitionRules are defined (rules-based machine), deny
           unmatched pairs to prevent silent fall-through
        4. If no rules exist at all (requires-only machine), allow for
           backward compatibility with simple state machines
        """
        if to_state not in self.states:
            return False

        target_state = self.states[to_state]

        # 1. Check explicit transition rules
        for rule in self.transitions:
            if rule.from_state == from_state and rule.to_state == to_state:
                return rule.can_transition(self._context)

        # 2. Fall back to state 'requires' field
        if target_state.requires:
            return from_state in target_state.requires

        # 3. Rules-based machine: no matching rule means transition not allowed
        if self.transitions:
            return False

        # 4. Requires-only machine with no requires on target: allow (backward compat)
        return True

    def transition_to(self, state_name: str, force: bool = False) -> bool:
        """Transition to a new state.

        Args:
            state_name: Target state name
            force: If True, bypass transition validation

        Returns:
            True if transition succeeded

        Raises:
            StateTransitionError: If transition is invalid or fails
        """
        # Hold the lock across the entire transition. A transition is a
        # check-then-act compound (can_transition -> action -> enter -> commit);
        # guarding only the final write would let a concurrent caller pass the
        # check and run setup/actions in parallel, corrupting the machine.
        with self._lock:
            # Check current state timeout
            if self.current_state.is_timed_out():
                _log.warning(f"Current state {self.current_state.name} has timed out")
                self.current_state.handle_timeout(self._context)

            if state_name not in self.states:
                raise StateTransitionError(f"Unknown state: {state_name}")

            target_state = self.states[state_name]
            previous_state = self.current_state.name

            # Check if transition is allowed (unless forced or invalid transitions allowed)
            if not force and not self.allow_invalid_transitions:
                if not self.can_transition(previous_state, state_name):
                    raise StateTransitionError(
                        f"Invalid transition: {previous_state} → {state_name}. "
                        f"Use force=True to bypass validation."
                    )

            # Execute transition action from rules
            for rule in self.transitions:
                if rule.from_state == previous_state and rule.to_state == state_name:
                    try:
                        rule.execute_action(self._context)
                    except Exception as e:
                        raise StateTransitionError(
                            f"Transition action failed: {previous_state} → {state_name}: {e}"
                        )

            _log.debug(
                f"Attempting state transition: {previous_state} → {state_name}"
                + (" [FORCED]" if force else "")
            )

            # Enter the target BEFORE exiting the current state. If entry fails
            # we raise without having run the old state's on_exit, so the
            # machine stays cleanly in its current state (no exit-without-
            # transition side effects).
            if not target_state.enter(self._context):
                raise StateTransitionError(
                    f"Failed to enter state: {state_name}. Setup callback returned False."
                )

            # Entry succeeded: exit the old state, then commit.
            self.current_state.exit(self._context)
            self.current_state = target_state
            self.state_history.append(state_name)
            self.transition_log.append(
                {
                    "from": previous_state,
                    "to": state_name,
                    "timestamp": time.time(),
                    "forced": force,
                }
            )

        _log.debug(f"State transition successful: {previous_state} → {state_name}")

        return True

    def set_state_no_setup(self, state_name: str) -> None:
        """Force state machine to a state without calling setup callbacks.

        Used when an external mechanism (e.g. StatefulFuzzer authenticator)
        has already performed the actions that the setup callback would do.
        Records the transition in history and log.
        """
        target_state = self.states.get(state_name)
        if target_state is None:
            raise StateTransitionError(f"Unknown state: {state_name}")

        with self._lock:
            previous_state = self.current_state.name
            self.current_state = target_state
            # Record entry time so is_timed_out()/timeout tracking keeps working
            # even though we skipped the setup callback.
            target_state.entry_time = time.time()
            self.state_history.append(state_name)
            self.transition_log.append(
                {
                    "from": previous_state,
                    "to": state_name,
                    "timestamp": time.time(),
                    "forced": True,
                }
            )
        _log.debug(f"State set (no setup): {previous_state} → {state_name}")

    def validate_current_state(self) -> bool:
        """Validate that we're still in the current state."""
        return self.current_state.validate(self._context)

    def require_state(self, state_name: str):
        """Ensure we're in the required state, transitioning if needed."""
        if self.current_state.name == state_name:
            # Already in required state, validate it
            if not self.validate_current_state():
                _log.warning(f"State validation failed for {state_name}, re-entering...")
                # Re-enter the state
                if not self.current_state.enter(self._context):
                    raise StateTransitionError(f"Failed to re-enter state: {state_name}")
            return

        # Need to transition
        self.transition_to(state_name)

    def traverse_to_state(self, target_state: str) -> bool:
        """Traverse multiple states to reach target state.

        Unlike require_state() which only does single-hop transitions,
        this finds the BFS path and transitions through each intermediate state.

        Args:
            target_state: Name of the target state to reach

        Returns:
            True ONLY if the machine actually ended up in ``target_state``.
            False if a transition step reported failure, or if the computed path
            leaves nothing to walk (e.g. the target sits *behind* the current
            state on the initial-state path) -- previously such cases returned
            True while the machine had not moved at all.

        Raises:
            StateTransitionError: If no path exists or a transition raises
        """
        # Hold the lock across the whole multi-hop walk: this is a
        # check-then-act sequence, and a concurrent transition would otherwise
        # move the machine out from under us mid-path. The lock is re-entrant,
        # so the nested transition_to() calls are fine.
        with self._lock:
            if self.current_state.name == target_state:
                if not self.validate_current_state():
                    _log.warning(f"State validation failed for {target_state}, re-entering...")
                    if not self.current_state.enter(self._context):
                        raise StateTransitionError(f"Failed to re-enter: {target_state}")
                return True

            path = self.get_path_to_state(target_state)
            if not path:
                raise StateTransitionError(
                    f"No path from {self.current_state.name} to {target_state}"
                )

            # get_path_to_state() returns a path rooted at the INITIAL state, so
            # the current state is not necessarily on it. When it is, resume from
            # there; when it is not, walk the whole path (index -1) rather than
            # skipping its first hop.
            try:
                current_idx = path.index(self.current_state.name)
            except ValueError:
                current_idx = -1

            remaining = path[current_idx + 1 :]
            if not remaining:
                # Nothing left to walk, yet we are not in the target (the
                # equality check above already returned). Never claim success.
                _log.fail(
                    f"No traversable steps from {self.current_state.name} to "
                    f"{target_state} (path={path})"
                )
                return False

            for state_name in remaining:
                if not self.transition_to(state_name):
                    _log.fail(
                        f"Transition to {state_name} failed while traversing to {target_state}"
                    )
                    return False

            # Only report success if the machine really ended in the target.
            reached = self.current_state.name == target_state
            if not reached:
                _log.fail(
                    f"Traversal to {target_state} ended in {self.current_state.name} (path={path})"
                )
            return reached

    def get_current_state_name(self) -> str:
        """Get the name of the current state"""
        return self.current_state.name

    def get_state_history(self) -> List[str]:
        """Get the history of state transitions"""
        return list(self.state_history)

    def reset_to_initial(self):
        """Reset to initial state."""
        with self._lock:
            initial_state = self._initial_state
            initial_state_name = initial_state.name
            self.current_state = initial_state
            # Re-entering the initial state restarts its timeout window; leaving
            # a stale entry_time would make is_timed_out() fire immediately on
            # the first transition after a reset.
            initial_state.entry_time = time.time()
            self.state_history = deque([initial_state_name], maxlen=1000)

        _log.debug(f"Resetting state machine to initial state: {initial_state_name}")

    def get_transition_log(self) -> List[Dict]:
        """Get detailed transition history with timestamps."""
        return list(self.transition_log)

    def get_transition_graph(self) -> Dict[str, List[str]]:
        """Get all valid transitions as a graph structure."""
        graph = {}
        for state_name in self.states:
            graph[state_name] = []
            for target_name in self.states:
                if state_name != target_name and self.can_transition(state_name, target_name):
                    graph[state_name].append(target_name)
        return graph

    def enable_invalid_state_testing(self):
        """Enable attack mode: allow invalid state transitions for fuzzing."""
        _log.debug("Invalid state testing enabled - state validation will be bypassed")
        self.allow_invalid_transitions = True

    def disable_invalid_state_testing(self):
        """Re-enable state validation after attack testing"""
        _log.debug("Invalid state testing disabled - state validation re-enabled")
        self.allow_invalid_transitions = False

    def get_valid_next_states(self) -> List[str]:
        """Get list of states that can be transitioned to from current state."""
        return self.get_transition_graph().get(self.current_state.name, [])

    def reset(self) -> None:
        """Reset to initial state, clearing history.

        Unlike reset_to_initial(), this also clears transition_log for
        a completely fresh start (useful for preflight state validation).
        """
        with self._lock:
            initial_state = self._initial_state
            initial_state_name = initial_state.name
            self.current_state = initial_state
            # See reset_to_initial(): restart the initial state's timeout window.
            initial_state.entry_time = time.time()
            self.state_history = deque([initial_state_name], maxlen=1000)
            self.transition_log = deque(maxlen=1000)

        _log.debug(f"Resetting state machine (full reset): {initial_state_name}")

    def get_topological_order(self) -> List[str]:
        """Return states sorted by dependency order (Kahn's algorithm).

        States are ordered so that dependencies (from 'requires' field)
        come before states that depend on them.

        NOTE on semantics: this treats EVERY ``requires`` entry as an edge, i.e.
        it answers "is the requires-graph acyclic, and what is a total order over
        it?". That is deliberately stricter than the OR reading ``requires`` has
        for *transition legality* (see :meth:`can_transition`) — a machine with
        legitimate loops (HTTP request/response) is acyclic under neither and
        raises here by design. Callers that want a traversal order which
        tolerates loops should fall back to :meth:`get_reachability_order`.

        Returns:
            List of state names in topological order

        Raises:
            ValueError: If circular dependencies detected
        """
        # Build in-degree count and adjacency list
        in_degree = {name: 0 for name in self.states}
        dependents = {name: [] for name in self.states}  # state -> states that depend on it

        for name, state in self.states.items():
            for req in state.requires:
                if req in self.states:
                    in_degree[name] += 1
                    dependents[req].append(name)

        # Start with states that have no dependencies
        queue = [name for name, degree in in_degree.items() if degree == 0]
        result = []

        while queue:
            # Sort queue for deterministic ordering
            queue.sort()
            current = queue.pop(0)
            result.append(current)

            # Reduce in-degree for dependent states
            for dependent in dependents[current]:
                in_degree[dependent] -= 1
                if in_degree[dependent] == 0:
                    queue.append(dependent)

        # Check for cycles
        if len(result) != len(self.states):
            remaining = [n for n in self.states if n not in result]
            raise ValueError(f"Circular dependency detected involving: {remaining}")

        return result

    def get_reachability_order(self) -> List[str]:
        """Return states in breadth-first reachability order from the initial state.

        This is the OR-semantics counterpart to :meth:`get_topological_order`.

        ``get_topological_order()`` treats every ``requires`` entry as a
        dependency edge and raises on cycles — useful for cycle *detection*,
        but unusable for machines with legitimate request/response loops (HTTP)
        where ``requires`` lists alternative predecessors. This method walks the
        graph with the same legality check transitions use
        (:meth:`can_transition`), so it never raises and always yields an order
        in which each state is preceded by at least one legal predecessor.

        Unreachable states are appended (sorted) at the end so callers still see
        every state.

        Returns:
            List of state names, initial state first
        """
        start = self._initial_state.name
        order = [start]
        seen = {start}
        queue: deque[str] = deque([start])

        while queue:
            current = queue.popleft()
            for next_state in sorted(self.states):
                if next_state in seen:
                    continue
                if self.can_transition(current, next_state):
                    seen.add(next_state)
                    order.append(next_state)
                    queue.append(next_state)

        # Unreachable leftovers still belong in the listing.
        order.extend(sorted(name for name in self.states if name not in seen))
        return order

    def get_path_to_state(self, target_state: str) -> List[str]:
        """Find the path from initial state to target state.

        Uses BFS to find shortest path respecting 'requires' dependencies.

        Args:
            target_state: Name of the target state

        Returns:
            List of state names forming the path (including target)
            Empty list if no path exists
        """
        if target_state not in self.states:
            return []

        initial_state = self._initial_state.name
        if target_state == initial_state:
            return [initial_state]

        # BFS to find path
        queue = deque([(initial_state, [initial_state])])
        visited = {initial_state}

        while queue:
            current, path = queue.popleft()

            # Get states we can transition to from current. Use can_transition()
            # — the same legality check transition_to() enforces — so the path we
            # return is guaranteed traversable. (For requires-only machines
            # can_transition falls back to the 'requires' field, preserving the
            # previous reachability semantics.)
            for next_state in self.states:
                if next_state in visited:
                    continue

                if self.can_transition(current, next_state):
                    new_path = path + [next_state]
                    if next_state == target_state:
                        return new_path
                    visited.add(next_state)
                    queue.append((next_state, new_path))

        return []  # No path found

    def __repr__(self):
        return (
            f"StateMachine(current={self.current_state.name}, "
            f"states={list(self.states.keys())}, "
            f"history={self.state_history}, "
            f"allow_invalid={self.allow_invalid_transitions})"
        )


def create_auth_state_machine(
    login_callback: Callable[[], bool],
    validate_callback: Optional[Callable[[], bool]] = None,
    connected_validation: Optional[Callable[[], bool]] = None,
    context: Optional["StateContext"] = None,
) -> StateMachine:
    """Create a simple two-state machine: CONNECTED → AUTHENTICATED.

    State Machine V2: Now accepts optional StateContext for response data
    propagation between state transitions.

    Args:
        login_callback: Callback to perform authentication
        validate_callback: Optional callback to validate auth state
        connected_validation: Optional callback to validate connection
        context: Optional StateContext for cross-state data access
    """
    connected = ProtocolState(
        name="CONNECTED",
        validation=connected_validation,
        description="TCP connection established",
    )

    authenticated = ProtocolState(
        name="AUTHENTICATED",
        setup=login_callback,
        validation=validate_callback,
        requires=["CONNECTED"],
        description="Authentication successful",
    )

    return StateMachine(initial_state=connected, states=[connected, authenticated], context=context)
