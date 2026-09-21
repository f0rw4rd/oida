"""Cryptographic state manager for protocol fuzzing.

Provides CryptoStateManager for nonce generation/tracking, security token
storage with expiry/refresh, and key derivation/management.
"""

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional
from datetime import datetime, timedelta
from enum import Enum, auto

from ....utils.ics_logger import get_logger

_log = get_logger("FUZZ", "crypto_state", 0)


class NonceStrategy(Enum):
    """Strategy for nonce generation and fuzzing."""

    RANDOM = auto()  # Cryptographically random
    INCREMENT = auto()  # Incrementing counter
    TIMESTAMP = auto()  # Timestamp-based
    ZERO = auto()  # All zeros (fuzz)
    MAX = auto()  # All 0xFF (fuzz)
    REPLAY = auto()  # Replay previous value (fuzz)


@dataclass
class NonceState:
    """State for a single nonce.

    Attributes:
        name: Nonce identifier
        value: Current nonce value
        length: Expected nonce length in bytes
        created_at: When nonce was generated
        strategy: Generation strategy
        fuzzable: Whether this nonce can be fuzzed
    """

    name: str
    value: bytes = b""
    length: int = 32
    created_at: datetime = field(default_factory=datetime.now)
    strategy: NonceStrategy = NonceStrategy.RANDOM
    fuzzable: bool = True


@dataclass
class TokenState:
    """State for a security token.

    Attributes:
        name: Token identifier
        value: Token value (bytes or any)
        expires_at: When token expires (None = no expiry)
        refresh_callback: Callback to refresh token when expired
        metadata: Additional token metadata
        lifetime: How long a refreshed value stays valid. Used to re-arm
            ``expires_at`` after a refresh; ``None`` means the refreshed value
            is treated as non-expiring.
    """

    name: str
    value: Any = None
    expires_at: Optional[datetime] = None
    refresh_callback: Optional[Callable[[], Any]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    lifetime: Optional[timedelta] = None

    def is_expired(self) -> bool:
        """Check if token has expired."""
        if self.expires_at is None:
            return False
        return datetime.now() > self.expires_at

    def time_until_expiry(self) -> Optional[timedelta]:
        """Get time until token expires."""
        if self.expires_at is None:
            return None
        return self.expires_at - datetime.now()


@dataclass
class KeyState:
    """State for a cryptographic key.

    Attributes:
        name: Key identifier
        value: Key material
        algorithm: Key algorithm (e.g., "AES-256-CBC")
        derived_from: Source key if this was derived
        metadata: Additional key metadata
    """

    name: str
    value: bytes = b""
    algorithm: str = ""
    derived_from: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class CryptoStateManager:
    """Manages cryptographic state for protocol fuzzing.

    Features:
    - Nonce generation and tracking with multiple strategies
    - Token storage with expiry and automatic refresh
    - Key derivation and storage
    - Fuzz support for all crypto values

    Example:
        crypto = CryptoStateManager()

        # Generate client nonce
        client_nonce = crypto.generate_nonce("client_nonce", length=32)

        # Store server nonce
        crypto.set_nonce("server_nonce", server_response.nonce)

        # Store security token with refresh
        crypto.set_token("security_token", TokenState(
            name="security_token",
            value=response.token,
            expires_at=datetime.now() + timedelta(hours=1),
            refresh_callback=lambda: refresh_channel()
        ))

        # Fuzz nonce
        crypto.fuzz_nonce("client_nonce", strategy=NonceStrategy.ZERO)
    """

    def __init__(self, name: str = "default"):
        """Initialize crypto state manager.

        Args:
            name: Manager name for logging
        """
        self.name = name
        self._nonces: Dict[str, NonceState] = {}
        self._tokens: Dict[str, TokenState] = {}
        self._keys: Dict[str, KeyState] = {}
        self._fuzz_overrides: Dict[str, bytes] = {}  # name -> fuzzed value

    # ==================== Nonce Management ====================

    def generate_nonce(
        self,
        name: str,
        length: int = 32,
        strategy: NonceStrategy = NonceStrategy.RANDOM,
    ) -> bytes:
        """Generate and store a nonce.

        Args:
            name: Nonce identifier
            length: Nonce length in bytes
            strategy: Generation strategy

        Returns:
            Generated nonce bytes
        """
        # Check for fuzz override first — skip generation entirely so internal
        # NonceState.value stays at the real counter/value and INCREMENT doesn't drift.
        if name in self._fuzz_overrides:
            return self._fuzz_overrides[name]

        import os

        if strategy == NonceStrategy.RANDOM:
            value = os.urandom(length)
        elif strategy == NonceStrategy.ZERO:
            value = b"\x00" * length
        elif strategy == NonceStrategy.MAX:
            value = b"\xff" * length
        elif strategy == NonceStrategy.INCREMENT:
            prev = self._nonces.get(name)
            if prev and prev.value:
                int_val = (int.from_bytes(prev.value, "big") + 1) % (1 << (length * 8))
                value = int_val.to_bytes(length, "big")
            else:
                value = b"\x00" * (length - 1) + b"\x01"
        elif strategy == NonceStrategy.TIMESTAMP:
            import struct
            import time

            ts = int(time.time() * 1000000)  # Microseconds
            ts_bytes = struct.pack(">Q", ts)
            value = ts_bytes + os.urandom(length - 8) if length > 8 else ts_bytes[:length]
        else:
            value = os.urandom(length)

        self._nonces[name] = NonceState(name=name, value=value, length=length, strategy=strategy)
        return value

    def set_nonce(self, name: str, value: bytes) -> None:
        """Store a nonce received from server.

        Args:
            name: Nonce identifier
            value: Nonce value
        """
        self._nonces[name] = NonceState(name=name, value=value, length=len(value))

    def get_nonce(self, name: str) -> Optional[bytes]:
        """Get stored nonce value.

        Args:
            name: Nonce identifier

        Returns:
            Nonce bytes or None if not found
        """
        nonce = self._nonces.get(name)
        if nonce:
            # Check for fuzz override
            if name in self._fuzz_overrides:
                return self._fuzz_overrides[name]
            return nonce.value
        return None

    def fuzz_nonce(self, name: str, strategy: NonceStrategy) -> None:
        """Set fuzzing strategy for a nonce.

        Args:
            name: Nonce identifier
            strategy: Fuzz strategy to apply
        """
        nonce = self._nonces.get(name)
        if not nonce:
            return

        length = nonce.length
        if strategy == NonceStrategy.ZERO:
            self._fuzz_overrides[name] = b"\x00" * length
        elif strategy == NonceStrategy.MAX:
            self._fuzz_overrides[name] = b"\xff" * length
        elif strategy == NonceStrategy.REPLAY:
            # Keep the current value as override (prevents regeneration)
            self._fuzz_overrides[name] = nonce.value

    def clear_fuzz_override(self, name: str) -> None:
        """Clear fuzz override for a nonce.

        Args:
            name: Nonce identifier
        """
        self._fuzz_overrides.pop(name, None)

    # ==================== Token Management ====================

    def set_token(self, name: str, token: TokenState) -> None:
        """Store a security token.

        Args:
            name: Token identifier
            token: TokenState instance
        """
        self._tokens[name] = token

    def get_token(self, name: str) -> Optional[TokenState]:
        """Get stored token, refreshing if expired.

        Args:
            name: Token identifier

        Returns:
            TokenState or None if not found
        """
        token = self._tokens.get(name)
        if token and token.is_expired() and token.refresh_callback:
            # Try to refresh
            try:
                new_value = token.refresh_callback()
                if isinstance(new_value, TokenState):
                    # Callback produced a whole replacement token: adopt its
                    # expiry and metadata, not just the value.
                    token.value = new_value.value
                    token.expires_at = new_value.expires_at
                    if new_value.metadata:
                        token.metadata.update(new_value.metadata)
                    if new_value.lifetime is not None:
                        token.lifetime = new_value.lifetime
                else:
                    token.value = new_value
                    # Re-arm the expiry. Without this the token stays expired
                    # forever, so every later get_token() call refreshes again
                    # -- an extra round trip (often a full re-auth) per message
                    # for the rest of the session -- and is_expired() keeps
                    # reporting True even though the value is fresh.
                    token.expires_at = (
                        datetime.now() + token.lifetime if token.lifetime is not None else None
                    )
            except Exception as e:
                # The stale value is returned below; say so loudly, because the
                # caller cannot distinguish it from a freshly refreshed one.
                _log.warning("Token refresh failed for '%s', using stale value: %s", name, e)
        return token

    def get_token_value(self, name: str) -> Optional[Any]:
        """Get token value directly.

        Args:
            name: Token identifier

        Returns:
            Token value or None
        """
        token = self.get_token(name)
        return token.value if token else None

    # ==================== Key Management ====================

    def set_key(
        self,
        name: str,
        value: bytes,
        algorithm: str = "",
        derived_from: Optional[str] = None,
    ) -> None:
        """Store a cryptographic key.

        Args:
            name: Key identifier
            value: Key material
            algorithm: Algorithm identifier
            derived_from: Source key if derived
        """
        self._keys[name] = KeyState(
            name=name, value=value, algorithm=algorithm, derived_from=derived_from
        )

    def get_key(self, name: str) -> Optional[bytes]:
        """Get stored key value.

        Args:
            name: Key identifier

        Returns:
            Key bytes or None
        """
        key = self._keys.get(name)
        return key.value if key else None

    def derive_key(
        self,
        name: str,
        from_key: str,
        derivation_func: Callable[[bytes], bytes],
        algorithm: str = "",
    ) -> bytes:
        """Derive a new key from an existing key.

        Args:
            name: New key identifier
            from_key: Source key name
            derivation_func: Function to derive new key
            algorithm: Algorithm identifier for new key

        Returns:
            Derived key bytes

        Raises:
            KeyError: If source key not found
        """
        source = self.get_key(from_key)
        if source is None:
            raise KeyError(f"Source key not found: {from_key}")

        derived = derivation_func(source)
        self.set_key(name, derived, algorithm, derived_from=from_key)
        return derived

    # ==================== Utility ====================

    def reset(self) -> None:
        """Clear all cryptographic state."""
        self._nonces.clear()
        self._tokens.clear()
        self._keys.clear()
        self._fuzz_overrides.clear()

    def to_dict(self) -> Dict[str, Any]:
        """Serialize for logging (without sensitive values)."""
        return {
            "name": self.name,
            "nonces": list(self._nonces.keys()),
            "tokens": list(self._tokens.keys()),
            "keys": list(self._keys.keys()),
            "fuzz_overrides": list(self._fuzz_overrides.keys()),
        }

    def __repr__(self) -> str:
        return (
            f"CryptoStateManager(name={self.name}, "
            f"nonces={len(self._nonces)}, "
            f"tokens={len(self._tokens)}, "
            f"keys={len(self._keys)})"
        )
