"""
Tests for SequenceManager, SequenceConfig, and SequenceDirection.

Tests cover:
- SequenceDirection enum values
- SequenceConfig dataclass
- SequenceManager: add_sequence, get, get_and_increment, set, reset
- SequenceManager: wrap behaviors (modulo, saturate, error)
- SequenceManager: serialization (to_dict, repr)
- SequenceManager: history tracking
"""

import pytest


# =============================================================================
# Test SequenceDirection
# =============================================================================


class TestSequenceDirection:
    """Tests for SequenceDirection enum."""

    def test_directions_exist(self):
        """All expected directions are defined."""
        from oida.fuzz.core.session.sequence import SequenceDirection

        assert SequenceDirection.SEND
        assert SequenceDirection.RECEIVE
        assert SequenceDirection.BOTH

    def test_directions_unique(self):
        """Direction values are unique."""
        from oida.fuzz.core.session.sequence import SequenceDirection

        values = [d.value for d in SequenceDirection]
        assert len(values) == len(set(values))


# =============================================================================
# Test SequenceConfig
# =============================================================================


class TestSequenceConfig:
    """Tests for SequenceConfig dataclass."""

    def test_default_config(self):
        """SequenceConfig has expected defaults."""
        from oida.fuzz.core.session.sequence import SequenceConfig, SequenceDirection

        cfg = SequenceConfig(name="test")
        assert cfg.name == "test"
        assert cfg.initial == 0
        assert cfg.min_value == 0
        assert cfg.max_value == 0xFFFF
        assert cfg.increment == 1
        assert cfg.direction == SequenceDirection.SEND
        assert cfg.wrap_behavior == "modulo"
        assert cfg.fuzzable is True

    def test_custom_config(self):
        """SequenceConfig with custom values."""
        from oida.fuzz.core.session.sequence import SequenceConfig, SequenceDirection

        cfg = SequenceConfig(
            name="recv_seq",
            initial=100,
            min_value=0,
            max_value=0x7FFF,
            increment=2,
            direction=SequenceDirection.RECEIVE,
            wrap_behavior="saturate",
            fuzzable=False,
        )
        assert cfg.name == "recv_seq"
        assert cfg.initial == 100
        assert cfg.max_value == 0x7FFF
        assert cfg.increment == 2
        assert cfg.direction == SequenceDirection.RECEIVE
        assert cfg.wrap_behavior == "saturate"
        assert cfg.fuzzable is False


# =============================================================================
# Test SequenceManager Basic Operations
# =============================================================================


class TestSequenceManagerCreation:
    """Tests for SequenceManager instantiation."""

    def test_default_creation(self):
        """SequenceManager created with default name."""
        from oida.fuzz.core.session.sequence import SequenceManager

        mgr = SequenceManager()
        assert mgr.name == "default"

    def test_named_creation(self):
        """SequenceManager created with custom name."""
        from oida.fuzz.core.session.sequence import SequenceManager

        mgr = SequenceManager("iec104")
        assert mgr.name == "iec104"


class TestSequenceManagerAddSequence:
    """Tests for adding sequences."""

    def test_add_sequence(self):
        """Add a sequence and verify it exists."""
        from oida.fuzz.core.session.sequence import SequenceManager, SequenceConfig

        mgr = SequenceManager()
        cfg = SequenceConfig(name="send_seq", initial=0, max_value=100)
        mgr.add_sequence(cfg)
        assert mgr.get("send_seq") == 0

    def test_add_multiple_sequences(self):
        """Add multiple sequences."""
        from oida.fuzz.core.session.sequence import SequenceManager, SequenceConfig

        mgr = SequenceManager()
        mgr.add_sequence(SequenceConfig(name="send", initial=0))
        mgr.add_sequence(SequenceConfig(name="recv", initial=10))
        assert mgr.get("send") == 0
        assert mgr.get("recv") == 10


class TestSequenceManagerGet:
    """Tests for getting sequence values."""

    def test_get_existing_sequence(self):
        """Get value of existing sequence."""
        from oida.fuzz.core.session.sequence import SequenceManager, SequenceConfig

        mgr = SequenceManager()
        mgr.add_sequence(SequenceConfig(name="seq1", initial=42))
        assert mgr.get("seq1") == 42

    def test_get_unknown_sequence_raises(self):
        """Get unknown sequence raises KeyError."""
        from oida.fuzz.core.session.sequence import SequenceManager

        mgr = SequenceManager()
        with pytest.raises(KeyError, match="Unknown sequence"):
            mgr.get("nonexistent")


class TestSequenceManagerGetAndIncrement:
    """Tests for get_and_increment."""

    def test_returns_current_and_increments(self):
        """get_and_increment returns current value then increments."""
        from oida.fuzz.core.session.sequence import SequenceManager, SequenceConfig

        mgr = SequenceManager()
        mgr.add_sequence(SequenceConfig(name="seq", initial=0, increment=1, max_value=100))

        val1 = mgr.get_and_increment("seq")
        assert val1 == 0
        val2 = mgr.get_and_increment("seq")
        assert val2 == 1
        val3 = mgr.get_and_increment("seq")
        assert val3 == 2

    def test_custom_increment(self):
        """Increment by custom step."""
        from oida.fuzz.core.session.sequence import SequenceManager, SequenceConfig

        mgr = SequenceManager()
        mgr.add_sequence(SequenceConfig(name="seq", initial=0, increment=2, max_value=100))

        val1 = mgr.get_and_increment("seq")
        assert val1 == 0
        val2 = mgr.get_and_increment("seq")
        assert val2 == 2
        assert mgr.get("seq") == 4

    def test_unknown_sequence_raises(self):
        """get_and_increment with unknown sequence raises KeyError."""
        from oida.fuzz.core.session.sequence import SequenceManager

        mgr = SequenceManager()
        with pytest.raises(KeyError, match="Unknown sequence"):
            mgr.get_and_increment("nonexistent")

    def test_modulo_wrap(self):
        """Modulo wrap-around when exceeding max_value."""
        from oida.fuzz.core.session.sequence import SequenceManager, SequenceConfig

        mgr = SequenceManager()
        mgr.add_sequence(
            SequenceConfig(name="seq", initial=9, increment=1, min_value=0, max_value=10)
        )

        val1 = mgr.get_and_increment("seq")  # Returns 9, next should be 10
        assert val1 == 9
        val2 = mgr.get_and_increment("seq")  # Returns 10, wraps to 0
        assert val2 == 10
        assert mgr.get("seq") == 0  # Wrapped around

    def test_saturate_wrap(self):
        """Saturate at max_value."""
        from oida.fuzz.core.session.sequence import SequenceManager, SequenceConfig

        mgr = SequenceManager()
        mgr.add_sequence(
            SequenceConfig(
                name="seq", initial=9, increment=1, max_value=10, wrap_behavior="saturate"
            )
        )
        mgr.get_and_increment("seq")  # 9 -> 10
        mgr.get_and_increment("seq")  # 10 -> saturated at 10
        assert mgr.get("seq") == 10

    def test_error_wrap_raises(self):
        """Error wrap behavior raises ValueError on overflow."""
        from oida.fuzz.core.session.sequence import SequenceManager, SequenceConfig

        mgr = SequenceManager()
        mgr.add_sequence(
            SequenceConfig(name="seq", initial=10, increment=1, max_value=10, wrap_behavior="error")
        )
        with pytest.raises(ValueError, match="overflow"):
            mgr.get_and_increment("seq")


class TestSequenceManagerSet:
    """Tests for setting sequence values."""

    def test_set_value(self):
        """Set sequence to specific value."""
        from oida.fuzz.core.session.sequence import SequenceManager, SequenceConfig

        mgr = SequenceManager()
        mgr.add_sequence(SequenceConfig(name="seq", initial=0))
        mgr.set("seq", 42)
        assert mgr.get("seq") == 42

    def test_set_unknown_sequence_raises(self):
        """Set unknown sequence raises KeyError."""
        from oida.fuzz.core.session.sequence import SequenceManager

        mgr = SequenceManager()
        with pytest.raises(KeyError, match="Unknown sequence"):
            mgr.set("nonexistent", 0)


class TestSequenceManagerReset:
    """Tests for resetting sequences."""

    def test_reset_restores_initial_values(self):
        """Reset restores all sequences to initial values."""
        from oida.fuzz.core.session.sequence import SequenceManager, SequenceConfig

        mgr = SequenceManager()
        mgr.add_sequence(SequenceConfig(name="send", initial=0))
        mgr.add_sequence(SequenceConfig(name="recv", initial=100))
        mgr.get_and_increment("send")
        mgr.get_and_increment("recv")
        mgr.reset()
        assert mgr.get("send") == 0
        assert mgr.get("recv") == 100

    def test_reset_clears_history(self):
        """Reset clears the history."""
        from oida.fuzz.core.session.sequence import SequenceManager, SequenceConfig

        mgr = SequenceManager()
        mgr.add_sequence(SequenceConfig(name="seq", initial=0))
        mgr.get_and_increment("seq")
        assert len(mgr._history) > 0
        mgr.reset()
        assert len(mgr._history) == 0


class TestSequenceManagerHistory:
    """Tests for history tracking."""

    def test_increment_records_history(self):
        """get_and_increment records history entry."""
        from oida.fuzz.core.session.sequence import SequenceManager, SequenceConfig

        mgr = SequenceManager()
        mgr.add_sequence(SequenceConfig(name="seq", initial=0, increment=1, max_value=100))
        mgr.get_and_increment("seq")
        assert len(mgr._history) == 1
        name, op, old, new = mgr._history[0]
        assert name == "seq"
        assert op == "increment"
        assert old == 0
        assert new == 1

    def test_set_records_history(self):
        """set records history entry."""
        from oida.fuzz.core.session.sequence import SequenceManager, SequenceConfig

        mgr = SequenceManager()
        mgr.add_sequence(SequenceConfig(name="seq", initial=0))
        mgr.set("seq", 50)
        assert len(mgr._history) == 1
        name, op, old, new = mgr._history[0]
        assert name == "seq"
        assert op == "set"
        assert old == 0
        assert new == 50


# =============================================================================
# Test SequenceManager Serialization
# =============================================================================


class TestSequenceManagerSerialization:
    """Tests for serialization."""

    def test_to_dict(self):
        """to_dict returns expected structure."""
        from oida.fuzz.core.session.sequence import SequenceManager, SequenceConfig

        mgr = SequenceManager("test")
        mgr.add_sequence(SequenceConfig(name="send", initial=0, max_value=0x7FFF))
        d = mgr.to_dict()
        assert d["name"] == "test"
        assert "send" in d["sequences"]
        assert d["sequences"]["send"]["current"] == 0
        assert d["sequences"]["send"]["max"] == 0x7FFF

    def test_repr(self):
        """repr shows useful info."""
        from oida.fuzz.core.session.sequence import SequenceManager, SequenceConfig

        mgr = SequenceManager("iec104")
        mgr.add_sequence(SequenceConfig(name="send_seq"))
        r = repr(mgr)
        assert "SequenceManager" in r
        assert "iec104" in r
        assert "send_seq" in r
