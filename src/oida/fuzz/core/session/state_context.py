"""State context for carrying response data between state transitions.

This module provides the StateContext class which serves as the central
data carrier for stateful protocol fuzzing. It persists across:
- State transitions within a single connection
- Multiple fuzz iterations (with optional reset)
- Parallel state dimensions (future)

Example Usage:
    # In OPC UA fuzzer
    def _open_secure_channel(self, ctx: StateContext) -> bool:
        response = self._send_and_receive()

        # Store response data in context for later use
        ctx.set("secure_channel_id", response.channel_id)
        ctx.set("token_id", response.token_id)
        ctx.set_response("OPN", ResponseData(
            raw=response.raw,
            parsed={"channel_id": response.channel_id}
        ))
        return True

    # Later, in session creation
    def _create_session(self, ctx: StateContext) -> bool:
        channel_id = ctx.get("secure_channel_id")
        token_id = ctx.get("token_id")
        # Use values from previous state...
"""

from dataclasses import dataclass, field
from typing import Any, Dict, Optional, List, Callable, TYPE_CHECKING
from datetime import datetime

from ....utils.ics_logger import get_logger

_log = get_logger("FUZZ", "state_context", 0)

if TYPE_CHECKING:
    pass


@dataclass
class ResponseData:
    """Parsed response data from server.

    Attributes:
        raw: Raw bytes received from server
        parsed: Protocol-specific parsed data (dict)
        timestamp: When response was received
        response_code: Protocol response code if applicable
        metadata: Additional protocol-specific metadata

    Example:
        response = ResponseData(
            raw=b'\\x00\\x01...',
            parsed={"channel_id": 123, "token_id": 456},
            response_code=0,
            metadata={"latency_ms": 42}
        )
    """

    raw: bytes = b""
    parsed: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    response_code: Optional[int] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def get(self, key: str, default: Any = None) -> Any:
        """Get parsed value by key.

        Args:
            key: Key to look up in parsed data
            default: Default value if key not found

        Returns:
            Value from parsed data or default
        """
        return self.parsed.get(key, default)

    def has_error(self) -> bool:
        """Check if response indicates an error.

        Returns:
            True if response_code indicates error (>= 400 or negative)
        """
        if self.response_code is None:
            return False
        return self.response_code >= 400 or self.response_code < 0

    def __repr__(self) -> str:
        code_str = f", code={self.response_code}" if self.response_code is not None else ""
        return f"ResponseData(len={len(self.raw)}, keys={list(self.parsed.keys())}{code_str})"


class StateContext:
    """Carries state data between transitions and across requests.

    StateContext is the central data carrier that persists across:
    - State transitions within a single connection
    - Multiple fuzz iterations (with optional reset)
    - Parent/child context hierarchy (for nested states)

    Features:
    - Key-value storage for arbitrary state data
    - Named response storage keyed by operation name
    - Parent context inheritance for hierarchical states
    - Change callbacks for monitoring
    - Serialization for logging/debugging

    Example:
        ctx = StateContext()

        # Store values
        ctx.set("channel_id", 123)
        ctx.set("authenticated", True)

        # Store response
        ctx.set_response("HELLO", ResponseData(raw=b'...', parsed={...}))

        # Retrieve values
        channel_id = ctx.get("channel_id")
        hello_response = ctx.get_response("HELLO")

        # Create child context for nested state
        child_ctx = ctx.create_child()
        child_ctx.set("session_id", 456)  # Only in child
        child_ctx.get("channel_id")  # Inherited from parent
    """

    def __init__(self, parent: Optional["StateContext"] = None):
        """Initialize state context.

        Args:
            parent: Optional parent context for inheritance
        """
        self._data: Dict[str, Any] = {}
        self._responses: Dict[str, ResponseData] = {}
        self._sequence_managers: Dict[str, Any] = {}  # Will be SequenceManager
        self._crypto_state: Optional[Any] = None  # Will be CryptoStateManager
        self._parent = parent
        self._creation_time = datetime.now()
        self._callbacks: Dict[str, List[Callable]] = {}

    # ==================== Data Access ====================

    def set(self, key: str, value: Any) -> None:
        """Set a value in the context.

        Args:
            key: Storage key
            value: Value to store
        """
        self._data[key] = value
        self._notify_callbacks("set", key, value)

    def get(self, key: str, default: Any = None) -> Any:
        """Get a value from context, falling back to parent if not found.

        Args:
            key: Storage key
            default: Default value if not found in context or parent

        Returns:
            Stored value or default
        """
        if key in self._data:
            return self._data[key]
        if self._parent:
            return self._parent.get(key, default)
        return default

    def has(self, key: str) -> bool:
        """Check if key exists in context or parent.

        Args:
            key: Key to check

        Returns:
            True if key exists in this context or any parent
        """
        if key in self._data:
            return True
        if self._parent:
            return self._parent.has(key)
        return False

    def remove(self, key: str) -> None:
        """Remove a key from the context (does not affect parent).

        Args:
            key: Key to remove
        """
        if key in self._data:
            del self._data[key]

    def clear(
        self, preserve_keys: Optional[List[str]] = None, clear_responses: bool = False
    ) -> None:
        """Clear context data, optionally preserving specific keys.

        Args:
            preserve_keys: Keys to preserve during clear (None = clear all)
            clear_responses: If True, also clear stored responses
        """
        if preserve_keys:
            preserved = {k: v for k, v in self._data.items() if k in preserve_keys}
            self._data = preserved
        else:
            self._data = {}
        if clear_responses:
            self._responses = {}

    def keys(self) -> List[str]:
        """Get all keys in this context (not including parent).

        Returns:
            List of keys
        """
        return list(self._data.keys())

    def all_keys(self) -> List[str]:
        """Get all keys including inherited from parent.

        Returns:
            List of all accessible keys
        """
        keys = set(self._data.keys())
        if self._parent:
            keys.update(self._parent.all_keys())
        return list(keys)

    # ==================== Response Storage ====================

    def set_response(self, operation: str, response: ResponseData) -> None:
        """Store response data for an operation.

        Args:
            operation: Operation name (e.g., "OPN", "CreateSession", "HELLO")
            response: Response data to store
        """
        self._responses[operation] = response
        self._notify_callbacks("response", operation, response)

    def get_response(self, operation: str) -> Optional[ResponseData]:
        """Get stored response for an operation.

        Args:
            operation: Operation name

        Returns:
            ResponseData or None if not found
        """
        if operation in self._responses:
            return self._responses[operation]
        if self._parent:
            return self._parent.get_response(operation)
        return None

    def get_last_response(self) -> Optional[ResponseData]:
        """Get the most recent response by timestamp.

        Returns:
            Most recent ResponseData or None
        """
        if not self._responses:
            if self._parent:
                return self._parent.get_last_response()
            return None
        return max(self._responses.values(), key=lambda r: r.timestamp)

    def response_keys(self) -> List[str]:
        """Get all response operation names.

        Returns:
            List of operation names with stored responses
        """
        return list(self._responses.keys())

    # ==================== Sequence Managers ====================

    def get_sequence_manager(self, name: str = "default") -> Any:
        """Get or create a sequence manager.

        Args:
            name: Sequence manager name (for protocols with multiple sequences)

        Returns:
            SequenceManager instance (creates empty one if not exists)
        """
        if name not in self._sequence_managers:
            # A child context shares its parent's sequence managers. Creating a
            # fresh one here would restart the counter at zero halfway through a
            # live connection, so a nested state would re-send sequence numbers
            # the peer has already seen.
            if self._parent is not None:
                return self._parent.get_sequence_manager(name)

            # Lazy import to avoid circular dependency
            from .sequence import SequenceManager

            self._sequence_managers[name] = SequenceManager(name)
        return self._sequence_managers[name]

    def register_sequence_manager(self, name: str, manager: Any) -> None:
        """Register a pre-configured sequence manager.

        Args:
            name: Manager name
            manager: SequenceManager instance
        """
        self._sequence_managers[name] = manager

    def has_sequence_manager(self, name: str = "default") -> bool:
        """Check if a sequence manager is registered.

        Args:
            name: Manager name

        Returns:
            True if manager exists
        """
        if name in self._sequence_managers:
            return True
        return self._parent is not None and self._parent.has_sequence_manager(name)

    # ==================== Crypto State ====================

    @property
    def crypto(self) -> Any:
        """Get or create crypto state manager.

        Returns:
            CryptoStateManager instance
        """
        if self._crypto_state is None:
            # A child context shares its parent's crypto state. Minting a fresh
            # manager here would hand a nested state empty nonces, keys and
            # session tokens while the connection those belong to is still open.
            if self._parent is not None:
                return self._parent.crypto

            # Lazy import to avoid circular dependency
            from .crypto_state import CryptoStateManager

            self._crypto_state = CryptoStateManager()
        return self._crypto_state

    def set_crypto_state(self, crypto: Any) -> None:
        """Set the crypto state manager.

        Args:
            crypto: CryptoStateManager instance
        """
        self._crypto_state = crypto

    def has_crypto_state(self) -> bool:
        """Check if crypto state manager is initialized.

        Returns:
            True if crypto state exists
        """
        if self._crypto_state is not None:
            return True
        return self._parent is not None and self._parent.has_crypto_state()

    # ==================== Callbacks ====================

    def on_change(self, event: str, callback: Callable) -> None:
        """Register callback for context changes.

        Args:
            event: Event type ("set", "response", "clear")
            callback: Callback function(event, key, value)
        """
        if event not in self._callbacks:
            self._callbacks[event] = []
        self._callbacks[event].append(callback)

    def _notify_callbacks(self, event: str, key: str, value: Any) -> None:
        """Notify registered callbacks."""
        for callback in self._callbacks.get(event, []):
            try:
                callback(event, key, value)
            except Exception as e:
                _log.debug("StateContext callback error for event '%s': %s", event, e)

    # ==================== Hierarchy ====================

    def create_child(self) -> "StateContext":
        """Create a child context that inherits from this one.

        Child contexts can override values but fall back to parent
        for values they don't have. Useful for nested states.

        Returns:
            New StateContext with this as parent
        """
        return StateContext(parent=self)

    @property
    def parent(self) -> Optional["StateContext"]:
        """Get parent context if any."""
        return self._parent

    def get_depth(self) -> int:
        """Get depth in context hierarchy (root = 0).

        Returns:
            Depth level
        """
        depth = 0
        current = self._parent
        while current:
            depth += 1
            current = current._parent
        return depth

    # ==================== Serialization ====================

    def to_dict(self) -> Dict[str, Any]:
        """Serialize context to dictionary for logging/debugging.

        Note: Values are truncated for display. Full values remain accessible
        through the context itself.

        Returns:
            Dictionary representation
        """
        return {
            "data": {k: self._truncate_value(v) for k, v in self._data.items()},
            "responses": list(self._responses.keys()),
            "sequences": list(self._sequence_managers.keys()),
            "has_crypto": self._crypto_state is not None,
            "has_parent": self._parent is not None,
            "depth": self.get_depth(),
            "age_seconds": (datetime.now() - self._creation_time).total_seconds(),
        }

    def _truncate_value(self, value: Any, max_len: int = 100) -> str:
        """Truncate value for display."""
        s = str(value)
        if len(s) > max_len:
            return s[:max_len] + "..."
        return s

    def __repr__(self) -> str:
        return (
            f"StateContext(keys={len(self._data)}, "
            f"responses={len(self._responses)}, "
            f"depth={self.get_depth()})"
        )
