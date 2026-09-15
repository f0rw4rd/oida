"""Stateful fuzzer base class for protocols with authentication and handshakes.

This module provides a base class that extends BaseFuzzer with:
- Configurable connection classes (StatefulConnection subclasses)
- Pluggable authentication strategies (ProtocolAuthenticator subclasses)
- Automatic authentication callbacks on new connections
- State-aware request execution (PRE_AUTH, AUTHENTICATED, custom states)
- Pre-flight state reachability validation
"""

import itertools
import time
from dataclasses import dataclass
from typing import Any, List, Optional, Set, Tuple, Type, Union

from .base_fuzzer import BaseFuzzer, CommonState, RequestInfo
from .config import FuzzerConfig
from .connections import ConnectionFactory
from .connections.stateful import StatefulConnection
from .auth import ProtocolAuthenticator
from .session.state_machine import StateTransitionError


class AuthenticationFailedError(Exception):
    """Raised when authentication fails and fuzzing cannot continue."""


# Monotonic source of connection identities. Never reused, unlike id(), whose
# values CPython recycles as soon as the previous object is collected — a freed
# connection's id landing on a live one would make a brand-new, unauthenticated
# connection compare equal to the previously authenticated one and silently skip
# authentication.
_CONN_UID_ATTR = "_oida_conn_uid"
_conn_uid_counter = itertools.count(1)


def _connection_uid(conn: Any) -> Any:
    """Return a stable, collision-free identity for a connection object.

    The uid is stamped onto the object on first use and lives exactly as long as
    the object does, so two distinct live connections can never share one, and a
    collected connection's uid can never be handed to its successor.

    Falls back to ``("id", id(conn))`` only for objects that reject attribute
    assignment (``__slots__`` / C extension types), which is no worse than the
    previous behaviour.
    """
    if conn is None:
        return None
    uid = getattr(conn, _CONN_UID_ATTR, None)
    if uid is not None:
        return uid
    uid = next(_conn_uid_counter)
    try:
        setattr(conn, _CONN_UID_ATTR, uid)
    except (AttributeError, TypeError):
        return ("id", id(conn))
    return uid


@dataclass
class StateReachabilityResult:
    """Result of testing whether a state can be reached."""

    state_name: str
    reachable: bool
    error: Optional[str] = None
    duration_ms: float = 0.0
    skipped: bool = False
    skip_reason: Optional[str] = None


class StatefulFuzzer(BaseFuzzer):
    """Base class for fuzzers with stateful connections and authentication.

    Stateful protocols must consume each reply to advance, so they get a more
    generous calibrated receive timeout.

    Provides state-aware request execution where requests can declare their
    required state (PRE_AUTH, AUTHENTICATED, custom states) and the fuzzer
    will automatically handle state transitions.

    Subclasses should define:
    - PROTOCOL_NAME: Protocol identifier (e.g., "ftp", "mqtt")
    - CONNECTION_CLASS: Optional StatefulConnection subclass for protocol handshakes
    - AUTHENTICATOR_CLASS: Optional ProtocolAuthenticator subclass for login
    - DEFAULT_REQUEST_STATE: Default state for requests without explicit requires_state

    State-Aware Execution:
        Requests can declare their required state via RequestInfo.requires_state:
        - None: Uses DEFAULT_REQUEST_STATE (AUTHENTICATED by default)
        - CommonState.PRE_AUTH: Skips authentication, runs in pre-auth phase
        - CommonState.AUTHENTICATED: Ensures authenticated before running
        - CommonState.ANY: No state enforcement
        - "CUSTOM_STATE": Protocol-specific state from StateMachine
        - ["STATE_A", "STATE_B"]: Multiple acceptable states (OR logic)

    Example:
        class FTPFuzzer(StatefulFuzzer):
            PROTOCOL_NAME = "ftp"
            CONNECTION_CLASS = FTPConnection
            AUTHENTICATOR_CLASS = FTPAuthenticator
            DEFAULT_REQUEST_STATE = CommonState.AUTHENTICATED

            @classmethod
            def get_request_definitions(cls) -> List[RequestInfo]:
                return [
                    RequestInfo("FTP_Auth_Fuzz", "...", requires_state=CommonState.PRE_AUTH),
                    RequestInfo("FTP_Critical_Path", "...", requires_state=CommonState.AUTHENTICATED),
                ]
    """

    # Stateful protocols need the reply to advance: use the generous recv-timeout basis.
    STATEFUL = True

    # Override these in subclasses
    PROTOCOL_NAME: str = "proto"
    CONNECTION_CLASS: Optional[Type[StatefulConnection]] = None
    AUTHENTICATOR_CLASS: Optional[Type[ProtocolAuthenticator]] = None

    # Default state for requests without explicit requires_state
    # Override in subclasses if different default is needed
    DEFAULT_REQUEST_STATE: CommonState = CommonState.AUTHENTICATED

    def __init__(
        self,
        config: FuzzerConfig,
        connection_factory: Optional[ConnectionFactory] = None,
    ):
        """Initialize stateful fuzzer.

        Args:
            config: Fuzzer configuration
            connection_factory: Optional connection factory (for testing)
        """
        # Create authenticator before parent init (may be needed in _define_protocol)
        self.authenticator = self._create_authenticator(config)

        # Track authentication state
        self._auth_failed = False
        self._auth_callback_registered = False
        # Track which connection+socket has been authenticated (for -R reuse mode)
        self._authenticated_conn_id = None

        # State tracking for state-aware requests
        self._current_state: str = CommonState.CONNECTED.value

        # Mapping from boofuzz node names to RequestInfo names
        # Protocols can populate this using _register_request_nodes()
        self._node_to_request_map: dict = {}

        # Call parent init (which calls _define_protocol and _define_state_machine)
        super().__init__(config, connection_factory)

        # Log initial state after full initialization
        self.log.debug(f"[STATE] StatefulFuzzer initialized - initial state: {self._current_state}")
        self.log.debug(f"[STATE] Default request state: {self.DEFAULT_REQUEST_STATE}")
        self.log.debug(
            f"[STATE] Authenticator: {self.AUTHENTICATOR_CLASS.__name__ if self.AUTHENTICATOR_CLASS else 'None'}"
        )
        self.log.debug(
            f"[STATE] State machine: {'Configured' if self.state_machine else 'Not configured'}"
        )

    # ==================== STATE TRACKING METHODS ====================

    def _get_current_state(self) -> str:
        """Get current protocol state.

        Returns:
            Current state name as string
        """
        # Prefer state machine's current state if available
        if self.state_machine:
            state = self.state_machine.get_current_state_name()
            self.log.debug(f"[STATE] Current state (from state machine): {state}")
            return state
        self.log.debug(f"[STATE] Current state (internal): {self._current_state}")
        return self._current_state

    def _set_state(self, state: Union[str, CommonState]) -> None:
        """Set current protocol state.

        Args:
            state: New state (string or CommonState enum)
        """
        old_state = self._get_current_state() if hasattr(self, "_current_state") else "UNKNOWN"
        state_name = state.value if isinstance(state, CommonState) else state

        self.log.debug(f"[STATE] Attempting state transition: {old_state} -> {state_name}")

        if self.state_machine and state_name in self.state_machine.states:
            try:
                self.state_machine.transition_to(state_name)
                self.log.debug(
                    f"[STATE] State machine transition successful: {old_state} -> {state_name}"
                )
            except StateTransitionError as e:
                # Keep internal state in sync with the state machine's actual state
                self._current_state = self.state_machine.get_current_state_name()
                self.log.warning(
                    f"[STATE] State machine transition failed ({e}), staying at {self._current_state}"
                )
        else:
            self._current_state = state_name
            if self.state_machine:
                self.log.debug(
                    f"[STATE] State '{state_name}' not in state machine, set internal state"
                )
            else:
                self.log.debug(f"[STATE] No state machine, set internal state: {state_name}")

    def _state_satisfied(self, required_name: str) -> bool:
        """Check whether a single required state name is currently satisfied.

        Two namespaces coexist:
        - Protocol-specific states tracked by the StateMachine (e.g. MQTT's
          DISCONNECTED/CONNECTED/READY). For these, the state machine is the
          authoritative source of truth.
        - Auth-layer CommonStates tracked in ``self._current_state``
          (PRE_AUTH / AUTHENTICATED / CONNECTED). These may have no literal
          counterpart in a protocol state machine, so a successful auth is only
          reflected here — the state machine cannot represent it.

        Consulting the owning namespace keeps a single source of truth per
        state and prevents re-authenticating every test case when the state
        machine has no "AUTHENTICATED" state.
        """
        if self.state_machine and required_name in self.state_machine.states:
            return self.state_machine.get_current_state_name() == required_name
        return self._current_state == required_name

    def _request_state_matches(self, request_info: RequestInfo) -> bool:
        """Check if current state matches request's required state.

        Args:
            request_info: Request info with requires_state field

        Returns:
            True if current state satisfies the requirement
        """
        required = request_info.requires_state

        # No requirement = use default
        if required is None:
            self.log.debug(
                f"[STATE] Request '{request_info.name}' has no explicit state, using default: {self.DEFAULT_REQUEST_STATE}"
            )
            required = self.DEFAULT_REQUEST_STATE

        # ANY = always matches
        if required == CommonState.ANY or required == "ANY":
            self.log.debug(
                f"[STATE] Request '{request_info.name}' requires ANY state - always matches"
            )
            return True

        # Handle list of acceptable states (OR logic)
        if isinstance(required, list):
            req_names = [s.value if isinstance(s, CommonState) else s for s in required]
            for req_name in req_names:
                if self._state_satisfied(req_name):
                    self.log.debug(
                        f"[STATE] Request '{request_info.name}' requires one of {req_names}, '{req_name}' MATCHES"
                    )
                    return True
            self.log.debug(
                f"[STATE] Request '{request_info.name}' requires one of {req_names}, none match"
            )
            return False

        # Single state requirement
        required_name = required.value if isinstance(required, CommonState) else required
        matches = self._state_satisfied(required_name)
        if matches:
            self.log.debug(
                f"[STATE] Request '{request_info.name}' requires '{required_name}' - MATCHES"
            )
        else:
            self.log.debug(
                f"[STATE] Request '{request_info.name}' requires '{required_name}' - does NOT match"
            )
        return matches

    def _ensure_state_for_request(self, request_info: RequestInfo) -> bool:
        """Ensure we're in the correct state for a request.

        Attempts to transition to the required state if not already there.

        Args:
            request_info: Request info with requires_state field

        Returns:
            True if state is correct or successfully transitioned
            False if state cannot be achieved
        """
        required = request_info.requires_state
        if required is None:
            required = self.DEFAULT_REQUEST_STATE

        self.log.debug(
            f"[STATE] Ensuring state for request '{request_info.name}', required: {required}"
        )

        if self._request_state_matches(request_info):
            self.log.debug(f"[STATE] Already in correct state for '{request_info.name}'")
            return True

        # Get the required state name(s)
        if isinstance(required, list):
            # For list, try the first state
            self.log.debug(
                f"[STATE] Request requires one of {required}, attempting first: {required[0]}"
            )
            required = required[0]

        required_name = required.value if isinstance(required, CommonState) else required
        current_state = self._get_current_state()
        self.log.debug(f"[STATE] Need to transition from '{current_state}' to '{required_name}'")

        # Special handling for PRE_AUTH - just set state, don't authenticate
        if required_name == CommonState.PRE_AUTH.value:
            self.log.debug("[STATE] PRE_AUTH requested - setting state without authentication")
            self._current_state = CommonState.PRE_AUTH.value
            return True

        # Special handling for AUTHENTICATED - perform authentication
        if required_name == CommonState.AUTHENTICATED.value:
            self.log.debug("[STATE] AUTHENTICATED requested - performing authentication")
            if self.authenticator:
                try:
                    conn = self.session.targets[0]._target_connection
                    self.log.debug("[STATE] Calling authenticator.authenticate() on connection")
                    if self.authenticator.authenticate(conn):
                        self._current_state = CommonState.AUTHENTICATED.value
                        # Also update state machine if it tracks AUTHENTICATED
                        sm = self.state_machine
                        if sm and "AUTHENTICATED" in sm.states:
                            sm.set_state_no_setup("AUTHENTICATED")
                        self.log.debug(
                            "[STATE] Authentication successful, state set to AUTHENTICATED"
                        )
                        return True
                    else:
                        self.log.debug("[STATE] Authentication returned False")
                except Exception as e:
                    self.log.fail(f"[STATE] Authentication exception: {e}")
            else:
                self.log.debug(
                    "[STATE] No authenticator configured, cannot achieve AUTHENTICATED state"
                )
            return False

        # Try state machine transition for protocol-specific states
        if self.state_machine and required_name in self.state_machine.states:
            self.log.debug(f"[STATE] Attempting state machine transition to '{required_name}'")
            try:
                self.state_machine.require_state(required_name)
                self.log.debug(f"[STATE] State machine transition to '{required_name}' successful")
                return True
            except StateTransitionError as e:
                self.log.warning(
                    f"[STATE] State machine cannot transition to '{required_name}': {e}"
                )
                return False

        self.log.warning(
            f"[STATE] Cannot achieve state '{required_name}' for request '{request_info.name}' - no transition path available"
        )
        return False

    def _register_request_nodes(self, request_name: str, *node_names: str) -> None:
        """Register boofuzz node names as belonging to a request.

        Protocols should call this method in _define_protocol() to map
        boofuzz node names to their RequestInfo for state tracking.

        Args:
            request_name: Name of the RequestInfo (e.g., "FTP_Auth_Fuzz")
            *node_names: Boofuzz node names that belong to this request

        Example:
            if self.is_request_enabled("FTP_Auth_Fuzz"):
                self._register_request_nodes("FTP_Auth_Fuzz", "USER", "PASS")
                self.session.connect(cmd_user)
                self.session.connect(cmd_pass)
        """
        for node_name in node_names:
            self._node_to_request_map[node_name] = request_name
            self.log.debug(f"[STATE] Registered node '{node_name}' -> request '{request_name}'")

    def _get_request_info_for_node(self, node_name: str) -> Optional[RequestInfo]:
        """Get RequestInfo for a given node/request name.

        First checks the node-to-request mapping (for protocols that use
        different names for nodes vs RequestInfo). Falls back to direct
        lookup in _available_requests.

        Args:
            node_name: Name of the boofuzz node/request

        Returns:
            RequestInfo if found, None otherwise
        """
        # First, check if this node is mapped to a request
        if node_name in self._node_to_request_map:
            request_name = self._node_to_request_map[node_name]
            info = self._available_requests.get(request_name)
            if info:
                self.log.debug(
                    f"[STATE] Node '{node_name}' -> request '{request_name}': requires_state={info.requires_state}"
                )
                return info

        # Fall back to direct lookup
        info = self._available_requests.get(node_name)
        if info:
            self.log.debug(
                f"[STATE] Found RequestInfo for '{node_name}': requires_state={info.requires_state}"
            )
        else:
            self.log.debug(f"[STATE] No RequestInfo for '{node_name}', using default state")
        return info

    # ==================== AUTHENTICATOR METHODS ====================

    def _create_authenticator(self, config: FuzzerConfig) -> Optional[ProtocolAuthenticator]:
        """Create protocol-specific authenticator from config options.

        Override this method in subclasses to customize authenticator creation.

        Args:
            config: Fuzzer configuration

        Returns:
            ProtocolAuthenticator instance or None if auth disabled
        """
        # Check if authentication is disabled
        if not config.get_option("use_auth", True):
            return None

        # Check if authenticator class is defined
        if not self.AUTHENTICATOR_CLASS:
            return None

        # Get credentials from config options
        username_key = f"{self.PROTOCOL_NAME}_username"
        password_key = f"{self.PROTOCOL_NAME}_password"

        # Try to get credentials - subclasses may have different option names
        username = config.get_option(username_key, "")
        password = config.get_option(password_key, "")

        # Only create authenticator if we have credentials or if it's optional auth
        # (like MQTT which can work without credentials)
        try:
            return self.AUTHENTICATOR_CLASS(
                username=username,
                password=password,
                protocol_name=self.PROTOCOL_NAME.upper(),
            )
        except TypeError:
            # Some authenticators have different signatures (e.g., MQTT)
            # Subclasses should override _create_authenticator for custom handling
            return None

    def _create_socket(self):
        """Create stateful connection with protocol handshake.

        Returns connection from CONNECTION_CLASS if defined, otherwise
        falls back to parent implementation.

        Returns:
            Connection object ready for fuzzing
        """
        if self.CONNECTION_CLASS:
            self.log.debug(f"Creating connection: {self.CONNECTION_CLASS.__name__}")
            conn = self.CONNECTION_CLASS(
                self.config.target_ip,
                self.config.target_port,
                protocol_name=self.PROTOCOL_NAME.upper(),
                **self._timeout_overrides(),
            )
            # Enable resilient mode if -R flag is set (handles EAGAIN/connection resets)
            if getattr(self.config, "reuse_target_connection", False):
                if hasattr(conn, "set_resilient"):
                    conn.set_resilient(True)
            return conn

        # Fall back to default connection
        return super()._create_socket()

    def _setup_auth_callback(self) -> None:
        """Register pre-send callback with state awareness.

        This callback is called before each test case is sent. It handles:
        - State-aware request execution (PRE_AUTH, AUTHENTICATED, custom states)
        - Re-authentication on new connections
        - State transitions for protocol-specific states
        """
        if self._auth_callback_registered:
            return

        self.log.debug("Registering state-aware authentication callback")

        def state_aware_pre_send(target, fuzz_data_logger, session, sock):
            """Pre-send callback that respects request state requirements."""
            self.log.debug("[STATE] === Pre-send callback triggered ===")

            # Get current request info
            current_node = session.fuzz_node
            if not current_node:
                self.log.debug("[STATE] No current fuzz node, skipping state check")
                return

            request_name = current_node.name
            self.log.debug(f"[STATE] Processing request: '{request_name}'")
            request_info = self._get_request_info_for_node(request_name)

            # If request not registered, create default info based on DEFAULT_REQUEST_STATE
            if not request_info:
                self.log.debug(
                    f"[STATE] Request '{request_name}' not in registry, using default state: {self.DEFAULT_REQUEST_STATE}"
                )
                request_info = RequestInfo(
                    name=request_name,
                    description="",
                    requires_state=self.DEFAULT_REQUEST_STATE,
                )
            else:
                self.log.debug(
                    f"[STATE] Found request info: requires_state={request_info.requires_state}"
                )

            required_state = request_info.requires_state
            if required_state is None:
                required_state = self.DEFAULT_REQUEST_STATE
                self.log.debug(f"[STATE] No explicit state, using default: {required_state}")

            # Handle PRE_AUTH - skip authentication entirely
            if required_state == CommonState.PRE_AUTH or required_state == "PRE_AUTH":
                self.log.debug(
                    f"[STATE] PRE_AUTH request '{request_name}': skipping authentication, setting state to PRE_AUTH"
                )
                self._current_state = CommonState.PRE_AUTH.value
                return

            # Handle ANY - don't enforce state
            if required_state == CommonState.ANY or required_state == "ANY":
                self.log.debug(
                    f"[STATE] ANY state request '{request_name}': no state enforcement needed"
                )
                return

            # Auth previously failed: only abort requests that actually REQUIRE
            # authentication. PRE_AUTH and ANY requests (handled above) need no
            # auth and must keep running so the rest of the campaign proceeds.
            if self._auth_failed:
                self.log.fail(
                    f"[STATE] Authentication previously failed, skipping auth-requiring "
                    f"request '{request_name}'"
                )
                raise AuthenticationFailedError("Authentication previously failed")

            # No authenticator configured - just track state
            if not self.authenticator:
                self.log.debug(
                    f"[STATE] No authenticator configured, skipping auth for '{request_name}'"
                )
                return

            # Get connection for state tracking
            conn = target._target_connection
            generation = getattr(conn, "_connection_generation", 0)
            conn_uid = _connection_uid(conn)
            current_identity = (conn_uid, generation)
            self.log.debug(f"[STATE] Connection identity: uid={conn_uid}, generation={generation}")

            # Handle AUTHENTICATED and protocol-specific states
            if current_identity != self._authenticated_conn_id:
                # New connection - need to set up state
                self.log.debug(
                    f"[STATE] New connection detected (prev={self._authenticated_conn_id}), need to establish state"
                )
                if not self._ensure_state_for_request(request_info):
                    self.log.fail(f"[STATE] Cannot achieve required state for '{request_name}'")
                    if self._auth_failed:
                        raise AuthenticationFailedError("Authentication failed")
                    # Mark as failed but don't exit - let fuzzer continue with other requests
                    self._handle_auth_failure()
                    return
                self._authenticated_conn_id = current_identity
                self.log.debug(
                    f"[STATE] State established, connection authenticated: {current_identity}"
                )
            else:
                # Same connection - verify state still valid
                self.log.debug("[STATE] Same connection, verifying state still valid")
                if not self._request_state_matches(request_info):
                    self.log.debug(
                        f"[STATE] State mismatch for '{request_name}', attempting to re-establish"
                    )
                    if not self._ensure_state_for_request(request_info):
                        self.log.warning(f"[STATE] Cannot re-establish state for '{request_name}'")
                    else:
                        self.log.debug(
                            f"[STATE] State re-established successfully for '{request_name}'"
                        )

        self.session._callback_monitor.on_pre_send.append(state_aware_pre_send)
        self._auth_callback_registered = True

    def _handle_auth_failure(self) -> None:
        """Handle authentication failure with helpful error messages."""
        self.log.debug(
            f"[STATE] Handling authentication failure, current state: {self._current_state}"
        )
        self.log.fail("Authentication failed")

        # Show credentials that were used
        if self.authenticator is None:
            return
        creds = self.authenticator.get_credentials()
        if "username" in creds:
            self.log.fail(f"Credentials: {creds.get('username', '')} / ***")
        elif "client_id" in creds:
            self.log.fail(f"Client ID: {creds.get('client_id', '')}")

        # Show help for setting credentials
        self.log.fail(
            f"Use --option {self.PROTOCOL_NAME}_username=<user> "
            f"--option {self.PROTOCOL_NAME}_password=<pass>"
        )
        self.log.fail("Or use --option use_auth=false to skip authentication")

        self._auth_failed = True

    def _preflight_check(self) -> tuple:
        """Run pre-flight check with state machine validation.

        Extends base class preflight check to also validate that all
        states in the state machine can be reached. This catches
        configuration issues early (wrong credentials, missing prerequisites).

        Returns:
            Tuple of (success: bool, error_msg: str or None)
        """
        # Run base connectivity checks first
        ok, err = super()._preflight_check()
        if not ok:
            return ok, err

        # State machine validation (if configured and verbose mode)
        if self.state_machine and getattr(self.config, "console_output", False):
            self.log.display("Running preflight state reachability check...")

            ok, results = self._preflight_state_check()
            self._display_state_results(results)

            # Get unreachable states
            unreachable = self._get_unreachable_states(results)

            if unreachable:
                # Filter requests that need unreachable states
                disabled = self._filter_requests_by_reachable_states(unreachable)

                if disabled:
                    self.log.warning(
                        f"Disabled {len(disabled)} requests requiring unreachable states:"
                    )
                    for name in disabled[:5]:  # Show first 5
                        self.log.warning(f"  - {name}")
                    if len(disabled) > 5:
                        self.log.warning(f"  ... and {len(disabled) - 5} more")

                # Check if any requests remain
                enabled_count = len(
                    [r for r in self._available_requests if r not in self._disabled_requests]
                )

                if enabled_count == 0:
                    return (
                        False,
                        "No requests available (all require unreachable states)",
                    )

                self.log.display(f"Continuing with {enabled_count} enabled requests")

        return True, None

    def fuzz_all(self) -> None:
        """Run fuzzing with authentication support.

        The session/auth-callback setup is deferred to _pre_fuzz_hook() (invoked
        by the base fuzz_all after timeout calibration) so the data socket
        captures the calibrated recv_timeout instead of the pre-calibration
        default; building the session eagerly here would freeze recv_timeout=5.0.
        """
        self.log.debug(f"[STATE] fuzz_all() called, current state: {self._current_state}")
        super().fuzz_all()

    def _pre_fuzz_hook(self) -> None:
        """Build the session + register the state-aware auth callback.

        Runs after the base fuzz_all has calibrated timeouts and immediately
        before the fuzz loop, so the lazily-built data socket picks up the
        calibrated recv_timeout.
        """
        # Access session to trigger lazy initialization (post-calibration).
        _ = self.session

        # Setup auth callback after session is created
        self._setup_auth_callback()

        # Log available requests and their state requirements
        self.log.debug("[STATE] Registered requests with state requirements:")
        for name, info in self._available_requests.items():
            state_str = (
                info.requires_state
                if info.requires_state
                else f"default ({self.DEFAULT_REQUEST_STATE})"
            )
            self.log.debug(f"[STATE]   - {name}: {state_str}")

    # ==================== STATE REACHABILITY VALIDATION ====================

    def _preflight_state_check(self) -> Tuple[bool, List[StateReachabilityResult]]:
        """Validate all state machine states can be reached.

        Tests each state in the state machine (except ERROR states) by:
        1. Finding the path from initial state to target state
        2. Traversing the path, calling enter() on each state
        3. Recording success/failure and timing

        This catches configuration issues early (wrong credentials,
        missing prerequisites, unreachable services).

        Returns:
            Tuple of (all_reachable: bool, results: List[StateReachabilityResult])
        """
        if not self.state_machine:
            return True, []

        results = []
        all_reachable = True

        # Get states in topological order (respects dependencies)
        # A cyclic requires-graph (HTTP's request/response loop, for example) is
        # legal — `requires` lists ALTERNATIVE predecessors, so a loop does not
        # make states unreachable. Fall back to breadth-first reachability order
        # instead of abandoning the whole check.
        try:
            ordered_states = self.state_machine.get_topological_order()
        except ValueError as e:
            self.log.debug(f"[STATE] No topological order ({e}); using reachability order instead")
            ordered_states = self.state_machine.get_reachability_order()

        # Use the authoritative initial state, not state_history[0]: the history
        # deque (maxlen=1000) evicts its left end after enough transitions.
        initial_state = self.state_machine.initial_state.name
        self.log.debug(f"[STATE] Testing reachability for {len(ordered_states)} states")

        for state_name in ordered_states:
            state = self.state_machine.states[state_name]
            result = StateReachabilityResult(state_name=state_name, reachable=False)

            # Skip ERROR states - they're not meant to be "reached"
            if state.is_error_state():
                result.skipped = True
                result.skip_reason = "error state"
                results.append(result)
                continue

            # Initial/CONNECTED state is always reachable
            if state_name == initial_state:
                result.reachable = True
                results.append(result)
                continue

            # Find path to this state
            path = self.state_machine.get_path_to_state(state_name)
            if not path:
                result.error = "no path from initial state"
                all_reachable = False
                results.append(result)
                continue

            # Check if any intermediate state in path was already tested as unreachable
            # This prevents re-testing paths we know will fail
            unreachable_in_path = [
                r.state_name
                for r in results
                if r.state_name in path and not r.reachable and not r.skipped
            ]
            if unreachable_in_path:
                result.skipped = True
                result.skip_reason = f"requires {unreachable_in_path[0]}"
                results.append(result)
                continue

            # Test reachability by traversing the path
            start_time = time.time()
            try:
                # Reset state machine to initial state
                self.state_machine.reset()

                # Traverse path (skip initial state, it's where we start)
                for step_state in path[1:]:
                    step = self.state_machine.states[step_state]

                    # Try to enter the state. Pass the state machine's context so
                    # context-style setup callbacks (def cb(self, ctx: StateContext))
                    # receive a real StateContext instead of None.
                    #
                    # enter() is called uniformly for setup and no-setup states:
                    # it refreshes entry_time on every successful entry (so a
                    # re-tested state never keeps a stale timestamp) and treats
                    # only an explicit `False` from the setup callback as failure
                    # (a callback returning None succeeded).
                    if not step.enter(self.state_machine.context):
                        if step_state == state_name:
                            result.error = "setup callback returned False"
                        else:
                            result.error = f"failed at intermediate state {step_state}"
                        break

                    # Update state machine's current state
                    self.state_machine.current_state = step
                    self.state_machine.state_history.append(step_state)

                    if step_state == state_name:
                        result.reachable = True

            except Exception as e:
                result.error = str(e)[:100]

            result.duration_ms = (time.time() - start_time) * 1000

            if not result.reachable and not result.skipped:
                all_reachable = False

            results.append(result)

        # Reset state machine after testing
        self.state_machine.reset()

        return all_reachable, results

    def _display_state_results(self, results: List[StateReachabilityResult]) -> None:
        """Display state reachability results.

        Args:
            results: List of StateReachabilityResult from _preflight_state_check
        """
        if not results or self.state_machine is None:
            return

        self.log.display(f"State machine: {len(results)} states defined")

        reachable_count = 0
        failed_count = 0
        skipped_count = 0

        for result in results:
            state = self.state_machine.states.get(result.state_name)
            has_setup = state.has_setup() if state else False

            if result.skipped:
                skipped_count += 1
                self.log.display(f"  [*] {result.state_name} - skipped ({result.skip_reason})")
            elif result.reachable:
                reachable_count += 1
                timing = f"{result.duration_ms:.0f}ms" if result.duration_ms > 0 else "0ms"
                setup_note = "" if has_setup else ", no setup"
                self.log.success(f"  {result.state_name} - reachable ({timing}{setup_note})")
            else:
                failed_count += 1
                error_msg = result.error or "unknown error"
                self.log.fail(f"  {result.state_name} - FAILED: {error_msg}")

        # Summary
        total_testable = reachable_count + failed_count
        self.log.display(
            f"State Summary: {reachable_count}/{total_testable} reachable, "
            f"{failed_count} failed, {skipped_count} skipped"
        )

        if failed_count > 0:
            self.log.warning("Some states unreachable - fuzzing may be incomplete")

    def _filter_requests_by_reachable_states(self, unreachable_states: Set[str]) -> List[str]:
        """Disable requests that require unreachable states.

        For each registered request, checks if its required state(s) are
        reachable. If ALL required states are unreachable (for OR logic),
        the request is disabled.

        Args:
            unreachable_states: Set of state names that couldn't be reached

        Returns:
            List of request names that were disabled
        """
        disabled = []

        for name, info in self._available_requests.items():
            required = info.requires_state

            # Use default if not specified
            if required is None:
                required = self.DEFAULT_REQUEST_STATE

            # ANY requests always work
            if required == CommonState.ANY or required == "ANY":
                continue

            # Normalize to list of state names
            if isinstance(required, CommonState):
                required_states = [required.value]
            elif isinstance(required, list):
                required_states = [s.value if isinstance(s, CommonState) else s for s in required]
            else:
                required_states = [required]

            # Check if ALL required states are unreachable
            # (for OR logic, only disable if all alternatives are unreachable)
            if all(s in unreachable_states for s in required_states):
                self._disabled_requests.add(name)
                disabled.append(name)

        return disabled

    def _get_unreachable_states(self, results: List[StateReachabilityResult]) -> Set[str]:
        """Extract set of unreachable state names from results.

        Args:
            results: List of StateReachabilityResult

        Returns:
            Set of state names that are not reachable (excluding skipped)
        """
        return {r.state_name for r in results if not r.reachable and not r.skipped}
