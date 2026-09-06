"""
Tests for CryptoStateManager, NonceState, TokenState, KeyState.

Tests cover:
- NonceStrategy enum
- NonceState dataclass
- TokenState: is_expired, time_until_expiry
- KeyState dataclass
- CryptoStateManager: nonce generation (all strategies)
- CryptoStateManager: nonce set/get/fuzz
- CryptoStateManager: token management with expiry and refresh
- CryptoStateManager: key management and derivation
- CryptoStateManager: reset, to_dict, repr
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock


# =============================================================================
# Test NonceStrategy
# =============================================================================


class TestNonceStrategy:
    """Tests for NonceStrategy enum."""

    def test_all_strategies_exist(self):
        """All expected nonce strategies are defined."""
        from oida.fuzz.core.session.crypto_state import NonceStrategy

        assert NonceStrategy.RANDOM
        assert NonceStrategy.INCREMENT
        assert NonceStrategy.TIMESTAMP
        assert NonceStrategy.ZERO
        assert NonceStrategy.MAX
        assert NonceStrategy.REPLAY

    def test_strategies_unique(self):
        """Strategy values are unique."""
        from oida.fuzz.core.session.crypto_state import NonceStrategy

        values = [s.value for s in NonceStrategy]
        assert len(values) == len(set(values))


# =============================================================================
# Test TokenState
# =============================================================================


class TestTokenState:
    """Tests for TokenState dataclass."""

    def test_not_expired_when_no_expiry(self):
        """Token without expiry is never expired."""
        from oida.fuzz.core.session.crypto_state import TokenState

        ts = TokenState(name="test", value="abc", expires_at=None)
        assert ts.is_expired() is False

    def test_not_expired_when_future(self):
        """Token with future expiry is not expired."""
        from oida.fuzz.core.session.crypto_state import TokenState

        ts = TokenState(name="test", value="abc", expires_at=datetime.now() + timedelta(hours=1))
        assert ts.is_expired() is False

    def test_expired_when_past(self):
        """Token with past expiry is expired."""
        from oida.fuzz.core.session.crypto_state import TokenState

        ts = TokenState(name="test", value="abc", expires_at=datetime.now() - timedelta(hours=1))
        assert ts.is_expired() is True

    def test_time_until_expiry_none(self):
        """time_until_expiry returns None when no expiry."""
        from oida.fuzz.core.session.crypto_state import TokenState

        ts = TokenState(name="test")
        assert ts.time_until_expiry() is None

    def test_time_until_expiry_positive(self):
        """time_until_expiry returns positive timedelta for future expiry."""
        from oida.fuzz.core.session.crypto_state import TokenState

        ts = TokenState(name="test", expires_at=datetime.now() + timedelta(hours=1))
        remaining = ts.time_until_expiry()
        assert remaining is not None
        assert remaining.total_seconds() > 0


# =============================================================================
# Test CryptoStateManager Nonce Operations
# =============================================================================


class TestCryptoNonceGeneration:
    """Tests for nonce generation."""

    def test_generate_random_nonce(self):
        """Generate random nonce."""
        from oida.fuzz.core.session.crypto_state import CryptoStateManager, NonceStrategy

        crypto = CryptoStateManager()
        nonce = crypto.generate_nonce("client_nonce", length=32, strategy=NonceStrategy.RANDOM)
        assert len(nonce) == 32
        assert isinstance(nonce, bytes)

    def test_generate_zero_nonce(self):
        """Generate all-zeros nonce."""
        from oida.fuzz.core.session.crypto_state import CryptoStateManager, NonceStrategy

        crypto = CryptoStateManager()
        nonce = crypto.generate_nonce("test", length=16, strategy=NonceStrategy.ZERO)
        assert nonce == b"\x00" * 16

    def test_generate_max_nonce(self):
        """Generate all-0xFF nonce."""
        from oida.fuzz.core.session.crypto_state import CryptoStateManager, NonceStrategy

        crypto = CryptoStateManager()
        nonce = crypto.generate_nonce("test", length=16, strategy=NonceStrategy.MAX)
        assert nonce == b"\xff" * 16

    def test_generate_increment_nonce_first_time(self):
        """First increment nonce starts at 1."""
        from oida.fuzz.core.session.crypto_state import CryptoStateManager, NonceStrategy

        crypto = CryptoStateManager()
        nonce = crypto.generate_nonce("counter", length=4, strategy=NonceStrategy.INCREMENT)
        assert nonce == b"\x00\x00\x00\x01"

    def test_generate_increment_nonce_subsequent(self):
        """Subsequent increment nonce increments value."""
        from oida.fuzz.core.session.crypto_state import CryptoStateManager, NonceStrategy

        crypto = CryptoStateManager()
        nonce1 = crypto.generate_nonce("counter", length=4, strategy=NonceStrategy.INCREMENT)
        nonce2 = crypto.generate_nonce("counter", length=4, strategy=NonceStrategy.INCREMENT)
        val1 = int.from_bytes(nonce1, "big")
        val2 = int.from_bytes(nonce2, "big")
        assert val2 == val1 + 1

    def test_generate_timestamp_nonce(self):
        """Generate timestamp-based nonce."""
        from oida.fuzz.core.session.crypto_state import CryptoStateManager, NonceStrategy

        crypto = CryptoStateManager()
        nonce = crypto.generate_nonce("ts_nonce", length=32, strategy=NonceStrategy.TIMESTAMP)
        assert len(nonce) == 32

    def test_generate_timestamp_nonce_short(self):
        """Generate short timestamp nonce (< 8 bytes)."""
        from oida.fuzz.core.session.crypto_state import CryptoStateManager, NonceStrategy

        crypto = CryptoStateManager()
        nonce = crypto.generate_nonce("ts_short", length=4, strategy=NonceStrategy.TIMESTAMP)
        assert len(nonce) == 4

    def test_generate_nonce_with_fuzz_override(self):
        """Fuzz override replaces generated nonce."""
        from oida.fuzz.core.session.crypto_state import CryptoStateManager, NonceStrategy

        crypto = CryptoStateManager()
        # Generate first to have a nonce to override
        crypto.generate_nonce("test", length=8, strategy=NonceStrategy.RANDOM)
        # Set fuzz override
        override = b"\xde\xad\xbe\xef" * 2
        crypto._fuzz_overrides["test"] = override
        # Next generation should return override
        result = crypto.generate_nonce("test", length=8, strategy=NonceStrategy.RANDOM)
        assert result == override


class TestCryptoNonceSetGet:
    """Tests for nonce set/get."""

    def test_set_and_get_nonce(self):
        """Store and retrieve a nonce."""
        from oida.fuzz.core.session.crypto_state import CryptoStateManager

        crypto = CryptoStateManager()
        crypto.set_nonce("server_nonce", b"\x01\x02\x03\x04")
        assert crypto.get_nonce("server_nonce") == b"\x01\x02\x03\x04"

    def test_get_missing_nonce_returns_none(self):
        """Get missing nonce returns None."""
        from oida.fuzz.core.session.crypto_state import CryptoStateManager

        crypto = CryptoStateManager()
        assert crypto.get_nonce("missing") is None

    def test_get_nonce_with_fuzz_override(self):
        """Get nonce returns fuzz override when set."""
        from oida.fuzz.core.session.crypto_state import CryptoStateManager

        crypto = CryptoStateManager()
        crypto.set_nonce("test", b"\x01\x02")
        crypto._fuzz_overrides["test"] = b"\xff\xff"
        assert crypto.get_nonce("test") == b"\xff\xff"


class TestCryptoNonceFuzzing:
    """Tests for nonce fuzzing."""

    def test_fuzz_nonce_zero(self):
        """Fuzz nonce with ZERO strategy."""
        from oida.fuzz.core.session.crypto_state import CryptoStateManager, NonceStrategy

        crypto = CryptoStateManager()
        crypto.set_nonce("test", b"\x01\x02\x03\x04")
        crypto.fuzz_nonce("test", NonceStrategy.ZERO)
        assert crypto.get_nonce("test") == b"\x00\x00\x00\x00"

    def test_fuzz_nonce_max(self):
        """Fuzz nonce with MAX strategy."""
        from oida.fuzz.core.session.crypto_state import CryptoStateManager, NonceStrategy

        crypto = CryptoStateManager()
        crypto.set_nonce("test", b"\x01\x02\x03\x04")
        crypto.fuzz_nonce("test", NonceStrategy.MAX)
        assert crypto.get_nonce("test") == b"\xff\xff\xff\xff"

    def test_fuzz_nonce_replay(self):
        """Fuzz nonce with REPLAY strategy keeps current value."""
        from oida.fuzz.core.session.crypto_state import CryptoStateManager, NonceStrategy

        crypto = CryptoStateManager()
        crypto.set_nonce("test", b"\xab\xcd")
        crypto.fuzz_nonce("test", NonceStrategy.REPLAY)
        assert crypto.get_nonce("test") == b"\xab\xcd"

    def test_fuzz_unknown_nonce_no_error(self):
        """Fuzzing unknown nonce does nothing."""
        from oida.fuzz.core.session.crypto_state import CryptoStateManager, NonceStrategy

        crypto = CryptoStateManager()
        crypto.fuzz_nonce("missing", NonceStrategy.ZERO)  # Should not raise

    def test_clear_fuzz_override(self):
        """Clear fuzz override restores original nonce value."""
        from oida.fuzz.core.session.crypto_state import CryptoStateManager, NonceStrategy

        crypto = CryptoStateManager()
        crypto.set_nonce("test", b"\x01\x02\x03\x04")
        crypto.fuzz_nonce("test", NonceStrategy.ZERO)
        assert crypto.get_nonce("test") == b"\x00\x00\x00\x00"
        crypto.clear_fuzz_override("test")
        assert crypto.get_nonce("test") == b"\x01\x02\x03\x04"


# =============================================================================
# Test CryptoStateManager Token Operations
# =============================================================================


class TestCryptoTokenManagement:
    """Tests for token management."""

    def test_set_and_get_token(self):
        """Store and retrieve a token."""
        from oida.fuzz.core.session.crypto_state import CryptoStateManager, TokenState

        crypto = CryptoStateManager()
        token = TokenState(name="security_token", value=b"\x01\x02")
        crypto.set_token("security_token", token)
        retrieved = crypto.get_token("security_token")
        assert retrieved is not None
        assert retrieved.value == b"\x01\x02"

    def test_get_missing_token_returns_none(self):
        """Get missing token returns None."""
        from oida.fuzz.core.session.crypto_state import CryptoStateManager

        crypto = CryptoStateManager()
        assert crypto.get_token("missing") is None

    def test_get_token_value(self):
        """get_token_value returns token value directly."""
        from oida.fuzz.core.session.crypto_state import CryptoStateManager, TokenState

        crypto = CryptoStateManager()
        crypto.set_token("t", TokenState(name="t", value="hello"))
        assert crypto.get_token_value("t") == "hello"

    def test_get_token_value_missing(self):
        """get_token_value returns None for missing token."""
        from oida.fuzz.core.session.crypto_state import CryptoStateManager

        crypto = CryptoStateManager()
        assert crypto.get_token_value("missing") is None

    def test_expired_token_with_refresh(self):
        """Expired token triggers refresh callback."""
        from oida.fuzz.core.session.crypto_state import CryptoStateManager, TokenState

        crypto = CryptoStateManager()
        callback = Mock(return_value="new_value")
        token = TokenState(
            name="t",
            value="old_value",
            expires_at=datetime.now() - timedelta(hours=1),
            refresh_callback=callback,
        )
        crypto.set_token("t", token)
        retrieved = crypto.get_token("t")
        assert retrieved.value == "new_value"
        callback.assert_called_once()

    def test_expired_token_refresh_failure_keeps_old(self):
        """Failed refresh keeps expired token."""
        from oida.fuzz.core.session.crypto_state import CryptoStateManager, TokenState

        crypto = CryptoStateManager()
        callback = Mock(side_effect=RuntimeError("refresh failed"))
        token = TokenState(
            name="t",
            value="old_value",
            expires_at=datetime.now() - timedelta(hours=1),
            refresh_callback=callback,
        )
        crypto.set_token("t", token)
        retrieved = crypto.get_token("t")
        assert retrieved.value == "old_value"  # Kept old value

    def test_non_expired_token_no_refresh(self):
        """Non-expired token does not trigger refresh."""
        from oida.fuzz.core.session.crypto_state import CryptoStateManager, TokenState

        crypto = CryptoStateManager()
        callback = Mock(return_value="new_value")
        token = TokenState(
            name="t",
            value="current",
            expires_at=datetime.now() + timedelta(hours=1),
            refresh_callback=callback,
        )
        crypto.set_token("t", token)
        retrieved = crypto.get_token("t")
        assert retrieved.value == "current"
        callback.assert_not_called()


# =============================================================================
# Test CryptoStateManager Key Operations
# =============================================================================


class TestCryptoKeyManagement:
    """Tests for key management."""

    def test_set_and_get_key(self):
        """Store and retrieve a key."""
        from oida.fuzz.core.session.crypto_state import CryptoStateManager

        crypto = CryptoStateManager()
        crypto.set_key("master", b"\x00" * 32, algorithm="AES-256-CBC")
        assert crypto.get_key("master") == b"\x00" * 32

    def test_get_missing_key_returns_none(self):
        """Get missing key returns None."""
        from oida.fuzz.core.session.crypto_state import CryptoStateManager

        crypto = CryptoStateManager()
        assert crypto.get_key("missing") is None

    def test_derive_key(self):
        """Derive a new key from an existing key."""
        from oida.fuzz.core.session.crypto_state import CryptoStateManager

        crypto = CryptoStateManager()
        crypto.set_key("master", b"\x01\x02\x03\x04")

        def derivation(key_bytes):
            return bytes(b ^ 0xFF for b in key_bytes)

        derived = crypto.derive_key("derived", "master", derivation, algorithm="XOR")
        assert derived == bytes([0xFE, 0xFD, 0xFC, 0xFB])
        assert crypto.get_key("derived") == derived

    def test_derive_from_missing_key_raises(self):
        """Derive from missing key raises KeyError."""
        from oida.fuzz.core.session.crypto_state import CryptoStateManager

        crypto = CryptoStateManager()
        with pytest.raises(KeyError, match="Source key not found"):
            crypto.derive_key("derived", "missing", lambda x: x)

    def test_key_metadata(self):
        """Key stores metadata correctly."""
        from oida.fuzz.core.session.crypto_state import CryptoStateManager

        crypto = CryptoStateManager()
        crypto.set_key("k", b"\x00" * 16, algorithm="AES-128", derived_from="parent_key")
        # Access internal state to verify metadata
        key_state = crypto._keys["k"]
        assert key_state.algorithm == "AES-128"
        assert key_state.derived_from == "parent_key"


# =============================================================================
# Test CryptoStateManager Utility Methods
# =============================================================================


class TestCryptoUtility:
    """Tests for utility methods."""

    def test_reset_clears_all(self):
        """Reset clears all crypto state."""
        from oida.fuzz.core.session.crypto_state import CryptoStateManager, TokenState

        crypto = CryptoStateManager()
        crypto.generate_nonce("n1", 8)
        crypto.set_token("t1", TokenState(name="t1", value="v"))
        crypto.set_key("k1", b"\x00")
        crypto._fuzz_overrides["n1"] = b"\xff"

        crypto.reset()
        assert crypto.get_nonce("n1") is None
        assert crypto.get_token("t1") is None
        assert crypto.get_key("k1") is None
        assert len(crypto._fuzz_overrides) == 0

    def test_to_dict(self):
        """to_dict returns expected structure without sensitive values."""
        from oida.fuzz.core.session.crypto_state import CryptoStateManager, TokenState

        crypto = CryptoStateManager("test")
        crypto.generate_nonce("n1", 8)
        crypto.set_token("t1", TokenState(name="t1", value="secret"))
        crypto.set_key("k1", b"\x00" * 32)

        d = crypto.to_dict()
        assert d["name"] == "test"
        assert "n1" in d["nonces"]
        assert "t1" in d["tokens"]
        assert "k1" in d["keys"]
        # Should not contain actual values
        assert "secret" not in str(d)
        assert b"\x00" not in str(d).encode()

    def test_repr(self):
        """repr shows useful info."""
        from oida.fuzz.core.session.crypto_state import CryptoStateManager, TokenState

        crypto = CryptoStateManager("test")
        crypto.generate_nonce("n", 8)
        crypto.set_token("t", TokenState(name="t"))
        r = repr(crypto)
        assert "CryptoStateManager" in r
        assert "test" in r
        assert "nonces=1" in r
        assert "tokens=1" in r
