"""
Tests for StateContext and ResponseData.

Tests cover:
- ResponseData: creation, get, has_error, repr
- StateContext: data access (set/get/has/remove/clear/keys)
- StateContext: response storage (set_response/get_response/get_last_response)
- StateContext: parent-child hierarchy and inheritance
- StateContext: sequence manager integration
- StateContext: crypto state integration
- StateContext: callbacks on change
- StateContext: serialization (to_dict)
"""

import time
from datetime import datetime


# =============================================================================
# Test ResponseData
# =============================================================================


class TestResponseDataCreation:
    """Tests for ResponseData instantiation."""

    def test_default_creation(self):
        """ResponseData can be created with defaults."""
        from src.oida.fuzz.core.session.state_context import ResponseData

        rd = ResponseData()
        assert rd.raw == b""
        assert rd.parsed == {}
        assert rd.response_code is None
        assert rd.metadata == {}

    def test_creation_with_values(self):
        """ResponseData can be created with specific values."""
        from src.oida.fuzz.core.session.state_context import ResponseData

        rd = ResponseData(
            raw=b"\x01\x02\x03",
            parsed={"channel_id": 123, "token": "abc"},
            response_code=200,
            metadata={"latency_ms": 42},
        )
        assert rd.raw == b"\x01\x02\x03"
        assert rd.parsed["channel_id"] == 123
        assert rd.response_code == 200
        assert rd.metadata["latency_ms"] == 42

    def test_timestamp_auto_set(self):
        """ResponseData timestamp is set automatically."""
        from src.oida.fuzz.core.session.state_context import ResponseData

        before = datetime.now()
        rd = ResponseData()
        after = datetime.now()
        assert before <= rd.timestamp <= after


class TestResponseDataGet:
    """Tests for ResponseData.get() method."""

    def test_get_existing_key(self):
        """Get existing parsed value."""
        from src.oida.fuzz.core.session.state_context import ResponseData

        rd = ResponseData(parsed={"channel_id": 123})
        assert rd.get("channel_id") == 123

    def test_get_missing_key_returns_default(self):
        """Get missing key returns default."""
        from src.oida.fuzz.core.session.state_context import ResponseData

        rd = ResponseData(parsed={"channel_id": 123})
        assert rd.get("missing") is None
        assert rd.get("missing", "fallback") == "fallback"


class TestResponseDataHasError:
    """Tests for ResponseData.has_error() method."""

    def test_no_error_when_code_none(self):
        """No error when response_code is None."""
        from src.oida.fuzz.core.session.state_context import ResponseData

        rd = ResponseData(response_code=None)
        assert rd.has_error() is False

    def test_no_error_for_success_codes(self):
        """No error for success response codes."""
        from src.oida.fuzz.core.session.state_context import ResponseData

        for code in [0, 200, 399]:
            rd = ResponseData(response_code=code)
            assert rd.has_error() is False, f"Code {code} should not be error"

    def test_error_for_400_and_above(self):
        """Error for response codes >= 400."""
        from src.oida.fuzz.core.session.state_context import ResponseData

        for code in [400, 404, 500]:
            rd = ResponseData(response_code=code)
            assert rd.has_error() is True, f"Code {code} should be error"

    def test_error_for_negative_codes(self):
        """Error for negative response codes."""
        from src.oida.fuzz.core.session.state_context import ResponseData

        rd = ResponseData(response_code=-1)
        assert rd.has_error() is True


class TestResponseDataRepr:
    """Tests for ResponseData.__repr__()."""

    def test_repr_without_code(self):
        """Repr without response code."""
        from src.oida.fuzz.core.session.state_context import ResponseData

        rd = ResponseData(raw=b"\x01\x02", parsed={"key": "val"})
        r = repr(rd)
        assert "len=2" in r
        assert "key" in r
        assert "code=" not in r

    def test_repr_with_code(self):
        """Repr with response code."""
        from src.oida.fuzz.core.session.state_context import ResponseData

        rd = ResponseData(raw=b"abc", response_code=200)
        r = repr(rd)
        assert "code=200" in r


# =============================================================================
# Test StateContext Data Access
# =============================================================================


class TestStateContextDataAccess:
    """Tests for StateContext set/get/has/remove/clear/keys operations."""

    def test_set_and_get(self):
        """Set and get a value."""
        from src.oida.fuzz.core.session.state_context import StateContext

        ctx = StateContext()
        ctx.set("key1", "value1")
        assert ctx.get("key1") == "value1"

    def test_get_missing_key_returns_default(self):
        """Get missing key returns default value."""
        from src.oida.fuzz.core.session.state_context import StateContext

        ctx = StateContext()
        assert ctx.get("missing") is None
        assert ctx.get("missing", 42) == 42

    def test_has_existing_key(self):
        """Has returns True for existing key."""
        from src.oida.fuzz.core.session.state_context import StateContext

        ctx = StateContext()
        ctx.set("key1", "value1")
        assert ctx.has("key1") is True

    def test_has_missing_key(self):
        """Has returns False for missing key."""
        from src.oida.fuzz.core.session.state_context import StateContext

        ctx = StateContext()
        assert ctx.has("missing") is False

    def test_remove_existing_key(self):
        """Remove existing key."""
        from src.oida.fuzz.core.session.state_context import StateContext

        ctx = StateContext()
        ctx.set("key1", "value1")
        ctx.remove("key1")
        assert ctx.has("key1") is False

    def test_remove_missing_key_no_error(self):
        """Removing missing key does not raise error."""
        from src.oida.fuzz.core.session.state_context import StateContext

        ctx = StateContext()
        ctx.remove("missing")  # Should not raise

    def test_clear_all(self):
        """Clear all data."""
        from src.oida.fuzz.core.session.state_context import StateContext

        ctx = StateContext()
        ctx.set("a", 1)
        ctx.set("b", 2)
        ctx.clear()
        assert ctx.keys() == []

    def test_clear_with_preserve(self):
        """Clear with preserved keys."""
        from src.oida.fuzz.core.session.state_context import StateContext

        ctx = StateContext()
        ctx.set("a", 1)
        ctx.set("b", 2)
        ctx.set("c", 3)
        ctx.clear(preserve_keys=["a", "c"])
        assert ctx.get("a") == 1
        assert ctx.get("b") is None
        assert ctx.get("c") == 3

    def test_keys(self):
        """Keys returns list of keys in this context."""
        from src.oida.fuzz.core.session.state_context import StateContext

        ctx = StateContext()
        ctx.set("x", 1)
        ctx.set("y", 2)
        assert sorted(ctx.keys()) == ["x", "y"]

    def test_overwrite_value(self):
        """Setting same key overwrites previous value."""
        from src.oida.fuzz.core.session.state_context import StateContext

        ctx = StateContext()
        ctx.set("key", "old")
        ctx.set("key", "new")
        assert ctx.get("key") == "new"

    def test_set_various_types(self):
        """Can store various data types."""
        from src.oida.fuzz.core.session.state_context import StateContext

        ctx = StateContext()
        ctx.set("int", 42)
        ctx.set("bytes", b"\x01\x02")
        ctx.set("dict", {"nested": True})
        ctx.set("list", [1, 2, 3])
        ctx.set("none", None)
        assert ctx.get("int") == 42
        assert ctx.get("bytes") == b"\x01\x02"
        assert ctx.get("dict") == {"nested": True}
        assert ctx.get("list") == [1, 2, 3]
        assert ctx.get("none") is None


# =============================================================================
# Test StateContext Response Storage
# =============================================================================


class TestStateContextResponseStorage:
    """Tests for response storage operations."""

    def test_set_and_get_response(self):
        """Store and retrieve response."""
        from src.oida.fuzz.core.session.state_context import StateContext, ResponseData

        ctx = StateContext()
        rd = ResponseData(raw=b"\x01", parsed={"id": 123})
        ctx.set_response("OPN", rd)
        retrieved = ctx.get_response("OPN")
        assert retrieved is rd
        assert retrieved.parsed["id"] == 123

    def test_get_missing_response_returns_none(self):
        """Get missing response returns None."""
        from src.oida.fuzz.core.session.state_context import StateContext

        ctx = StateContext()
        assert ctx.get_response("MISSING") is None

    def test_response_keys(self):
        """Response keys returns stored operation names."""
        from src.oida.fuzz.core.session.state_context import StateContext, ResponseData

        ctx = StateContext()
        ctx.set_response("HELLO", ResponseData())
        ctx.set_response("AUTH", ResponseData())
        assert sorted(ctx.response_keys()) == ["AUTH", "HELLO"]

    def test_get_last_response(self):
        """Get last response returns most recent by timestamp."""
        from src.oida.fuzz.core.session.state_context import StateContext, ResponseData

        ctx = StateContext()
        earlier = ResponseData(raw=b"first")
        time.sleep(0.01)
        later = ResponseData(raw=b"second")
        ctx.set_response("FIRST", earlier)
        ctx.set_response("SECOND", later)
        last = ctx.get_last_response()
        assert last.raw == b"second"

    def test_get_last_response_empty_returns_none(self):
        """Get last response when empty returns None."""
        from src.oida.fuzz.core.session.state_context import StateContext

        ctx = StateContext()
        assert ctx.get_last_response() is None


# =============================================================================
# Test StateContext Parent-Child Hierarchy
# =============================================================================


class TestStateContextHierarchy:
    """Tests for parent-child context hierarchy."""

    def test_create_child(self):
        """Create child context."""
        from src.oida.fuzz.core.session.state_context import StateContext

        parent = StateContext()
        child = parent.create_child()
        assert child.parent is parent

    def test_child_inherits_parent_values(self):
        """Child inherits values from parent."""
        from src.oida.fuzz.core.session.state_context import StateContext

        parent = StateContext()
        parent.set("channel_id", 123)
        child = parent.create_child()
        assert child.get("channel_id") == 123

    def test_child_can_override_parent(self):
        """Child can override parent values."""
        from src.oida.fuzz.core.session.state_context import StateContext

        parent = StateContext()
        parent.set("mode", "parent")
        child = parent.create_child()
        child.set("mode", "child")
        assert child.get("mode") == "child"
        assert parent.get("mode") == "parent"

    def test_child_has_checks_parent(self):
        """Has checks parent context."""
        from src.oida.fuzz.core.session.state_context import StateContext

        parent = StateContext()
        parent.set("parent_key", True)
        child = parent.create_child()
        assert child.has("parent_key") is True

    def test_child_response_inherits_from_parent(self):
        """Child can access parent responses."""
        from src.oida.fuzz.core.session.state_context import StateContext, ResponseData

        parent = StateContext()
        parent.set_response("HELLO", ResponseData(raw=b"hello"))
        child = parent.create_child()
        response = child.get_response("HELLO")
        assert response.raw == b"hello"

    def test_get_depth_root(self):
        """Root context depth is 0."""
        from src.oida.fuzz.core.session.state_context import StateContext

        ctx = StateContext()
        assert ctx.get_depth() == 0

    def test_get_depth_nested(self):
        """Nested contexts have correct depth."""
        from src.oida.fuzz.core.session.state_context import StateContext

        root = StateContext()
        child1 = root.create_child()
        child2 = child1.create_child()
        assert child1.get_depth() == 1
        assert child2.get_depth() == 2

    def test_all_keys_includes_parent(self):
        """all_keys includes parent keys."""
        from src.oida.fuzz.core.session.state_context import StateContext

        parent = StateContext()
        parent.set("parent_key", 1)
        child = parent.create_child()
        child.set("child_key", 2)
        all_k = child.all_keys()
        assert "parent_key" in all_k
        assert "child_key" in all_k

    def test_remove_in_child_does_not_affect_parent(self):
        """Remove in child does not affect parent."""
        from src.oida.fuzz.core.session.state_context import StateContext

        parent = StateContext()
        parent.set("key", "value")
        child = parent.create_child()
        child.set("key", "overridden")
        child.remove("key")
        # Child removed its own override, falls back to parent
        assert child.get("key") == "value"
        assert parent.get("key") == "value"

    def test_get_last_response_falls_back_to_parent(self):
        """get_last_response falls back to parent when child has no responses."""
        from src.oida.fuzz.core.session.state_context import StateContext, ResponseData

        parent = StateContext()
        parent.set_response("X", ResponseData(raw=b"from_parent"))
        child = parent.create_child()
        last = child.get_last_response()
        assert last.raw == b"from_parent"


# =============================================================================
# Test StateContext Callbacks
# =============================================================================


class TestStateContextCallbacks:
    """Tests for change callbacks."""

    def test_set_callback_fires(self):
        """Callback fires on set."""
        from src.oida.fuzz.core.session.state_context import StateContext

        ctx = StateContext()
        calls = []
        ctx.on_change("set", lambda evt, key, val: calls.append((evt, key, val)))
        ctx.set("foo", "bar")
        assert len(calls) == 1
        assert calls[0] == ("set", "foo", "bar")

    def test_response_callback_fires(self):
        """Callback fires on set_response."""
        from src.oida.fuzz.core.session.state_context import StateContext, ResponseData

        ctx = StateContext()
        calls = []
        ctx.on_change("response", lambda evt, key, val: calls.append((evt, key)))
        ctx.set_response("OPN", ResponseData())
        assert len(calls) == 1
        assert calls[0] == ("response", "OPN")

    def test_callback_error_does_not_break_set(self):
        """Callback error does not prevent set from working."""
        from src.oida.fuzz.core.session.state_context import StateContext

        ctx = StateContext()

        def bad_callback(evt, key, val):
            raise RuntimeError("Callback error")

        ctx.on_change("set", bad_callback)
        ctx.set("key", "value")  # Should not raise
        assert ctx.get("key") == "value"

    def test_multiple_callbacks(self):
        """Multiple callbacks are all invoked."""
        from src.oida.fuzz.core.session.state_context import StateContext

        ctx = StateContext()
        calls1 = []
        calls2 = []
        ctx.on_change("set", lambda e, k, v: calls1.append(k))
        ctx.on_change("set", lambda e, k, v: calls2.append(k))
        ctx.set("test", 1)
        assert calls1 == ["test"]
        assert calls2 == ["test"]


# =============================================================================
# Test StateContext Sequence Manager Integration
# =============================================================================


class TestStateContextSequenceManager:
    """Tests for sequence manager integration."""

    def test_get_creates_default_manager(self):
        """get_sequence_manager creates a default manager if not exists."""
        from src.oida.fuzz.core.session.state_context import StateContext

        ctx = StateContext()
        mgr = ctx.get_sequence_manager()
        assert mgr is not None
        assert mgr.name == "default"

    def test_get_named_manager(self):
        """Get named sequence manager."""
        from src.oida.fuzz.core.session.state_context import StateContext

        ctx = StateContext()
        mgr = ctx.get_sequence_manager("iec104")
        assert mgr.name == "iec104"

    def test_register_manager(self):
        """Register a pre-configured sequence manager."""
        from src.oida.fuzz.core.session.state_context import StateContext
        from src.oida.fuzz.core.session.sequence import SequenceManager

        ctx = StateContext()
        custom_mgr = SequenceManager("custom")
        ctx.register_sequence_manager("custom", custom_mgr)
        assert ctx.get_sequence_manager("custom") is custom_mgr

    def test_has_sequence_manager(self):
        """has_sequence_manager checks existence."""
        from src.oida.fuzz.core.session.state_context import StateContext

        ctx = StateContext()
        assert ctx.has_sequence_manager("default") is False
        ctx.get_sequence_manager("default")
        assert ctx.has_sequence_manager("default") is True


# =============================================================================
# Test StateContext Crypto State Integration
# =============================================================================


class TestStateContextCryptoState:
    """Tests for crypto state integration."""

    def test_crypto_creates_default(self):
        """crypto property creates CryptoStateManager on first access."""
        from src.oida.fuzz.core.session.state_context import StateContext

        ctx = StateContext()
        crypto = ctx.crypto
        assert crypto is not None
        assert crypto.name == "default"

    def test_crypto_is_cached(self):
        """crypto returns same instance on repeated access."""
        from src.oida.fuzz.core.session.state_context import StateContext

        ctx = StateContext()
        c1 = ctx.crypto
        c2 = ctx.crypto
        assert c1 is c2

    def test_set_crypto_state(self):
        """set_crypto_state replaces crypto manager."""
        from src.oida.fuzz.core.session.state_context import StateContext
        from src.oida.fuzz.core.session.crypto_state import CryptoStateManager

        ctx = StateContext()
        custom = CryptoStateManager("custom")
        ctx.set_crypto_state(custom)
        assert ctx.crypto is custom

    def test_has_crypto_state_before_access(self):
        """has_crypto_state returns False before first access."""
        from src.oida.fuzz.core.session.state_context import StateContext

        ctx = StateContext()
        assert ctx.has_crypto_state() is False

    def test_has_crypto_state_after_access(self):
        """has_crypto_state returns True after access."""
        from src.oida.fuzz.core.session.state_context import StateContext

        ctx = StateContext()
        _ = ctx.crypto
        assert ctx.has_crypto_state() is True


# =============================================================================
# Test StateContext Serialization
# =============================================================================


class TestStateContextSerialization:
    """Tests for to_dict and repr."""

    def test_to_dict_basic(self):
        """to_dict returns expected structure."""
        from src.oida.fuzz.core.session.state_context import StateContext, ResponseData

        ctx = StateContext()
        ctx.set("key1", "value1")
        ctx.set_response("OPN", ResponseData())

        d = ctx.to_dict()
        assert "data" in d
        assert "responses" in d
        assert "sequences" in d
        assert "has_crypto" in d
        assert "has_parent" in d
        assert "depth" in d
        assert "age_seconds" in d
        assert d["has_parent"] is False
        assert d["depth"] == 0
        assert "OPN" in d["responses"]

    def test_to_dict_truncates_long_values(self):
        """to_dict truncates long values."""
        from src.oida.fuzz.core.session.state_context import StateContext

        ctx = StateContext()
        ctx.set("long_key", "x" * 200)
        d = ctx.to_dict()
        assert len(d["data"]["long_key"]) <= 103  # 100 + "..."

    def test_repr(self):
        """repr shows useful info."""
        from src.oida.fuzz.core.session.state_context import StateContext

        ctx = StateContext()
        ctx.set("a", 1)
        r = repr(ctx)
        assert "StateContext" in r
        assert "keys=1" in r
