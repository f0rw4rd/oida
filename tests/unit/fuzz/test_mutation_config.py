"""
Tests for MutationStrategy and MutationConfig.

Tests cover:
- MutationStrategy: dataclass creation, validation, from_config
- MutationConfig: singleton behavior, properties, reset
- Global functions: enable_radamsa, disable_radamsa, set_mutation_seed
"""

import pytest
from unittest.mock import Mock


# =============================================================================
# Test MutationStrategy
# =============================================================================


class TestMutationStrategyCreation:
    """Tests for MutationStrategy dataclass."""

    def test_default_creation(self):
        """MutationStrategy defaults."""
        from oida.fuzz.core.mutation.config import MutationStrategy

        ms = MutationStrategy()
        assert ms.use_radamsa is False
        assert ms.mutation_count == 200

    def test_custom_creation(self):
        """MutationStrategy with custom values."""
        from oida.fuzz.core.mutation.config import MutationStrategy

        ms = MutationStrategy(use_radamsa=True, mutation_count=500)
        assert ms.use_radamsa is True
        assert ms.mutation_count == 500

    def test_invalid_mutation_count(self):
        """Mutation count < 1 raises ValueError."""
        from oida.fuzz.core.mutation.config import MutationStrategy

        with pytest.raises(ValueError, match="Mutation count must be >= 1"):
            MutationStrategy(mutation_count=0)
        with pytest.raises(ValueError, match="Mutation count must be >= 1"):
            MutationStrategy(mutation_count=-5)

    def test_is_radamsa_available(self):
        """is_radamsa_available always returns True (native impl)."""
        from oida.fuzz.core.mutation.config import MutationStrategy

        ms = MutationStrategy()
        assert ms.is_radamsa_available() is True


class TestMutationStrategyFromConfig:
    """Tests for MutationStrategy.from_config()."""

    def test_from_config_defaults(self):
        """from_config with no options uses defaults."""
        from oida.fuzz.core.mutation.config import MutationStrategy

        config = Mock()
        config.get_option = Mock(side_effect=lambda key, default: default)
        ms = MutationStrategy.from_config(config)
        assert ms.use_radamsa is False
        assert ms.mutation_count == 200

    def test_from_config_radamsa_enabled(self):
        """from_config with radamsa enabled."""
        from oida.fuzz.core.mutation.config import MutationStrategy

        config = Mock()
        config.get_option = Mock(
            side_effect=lambda key, default: {
                "use_radamsa": True,
                "radamsa_mutation_count": 500,
            }.get(key, default)
        )

        ms = MutationStrategy.from_config(config)
        assert ms.use_radamsa is True
        assert ms.mutation_count == 500


# =============================================================================
# Test MutationConfig Singleton
# =============================================================================


class TestMutationConfig:
    """Tests for MutationConfig singleton."""

    def test_singleton_pattern(self):
        """MutationConfig is a singleton."""
        from oida.fuzz.core.mutation.config import MutationConfig

        c1 = MutationConfig()
        c2 = MutationConfig()
        assert c1 is c2

    def test_default_values(self):
        """MutationConfig has expected defaults."""
        from oida.fuzz.core.mutation.config import MutationConfig

        config = MutationConfig()
        config.reset()
        assert config.use_radamsa is False
        assert config.radamsa_mutation_count == 200
        assert config.seed is None

    def test_set_use_radamsa(self):
        """Set use_radamsa property."""
        from oida.fuzz.core.mutation.config import MutationConfig

        config = MutationConfig()
        config.use_radamsa = True
        assert config.use_radamsa is True
        config.reset()

    def test_set_mutation_count(self):
        """Set radamsa_mutation_count property."""
        from oida.fuzz.core.mutation.config import MutationConfig

        config = MutationConfig()
        config.radamsa_mutation_count = 300
        assert config.radamsa_mutation_count == 300
        config.reset()

    def test_invalid_mutation_count(self):
        """Invalid mutation count raises ValueError."""
        from oida.fuzz.core.mutation.config import MutationConfig

        config = MutationConfig()
        with pytest.raises(ValueError):
            config.radamsa_mutation_count = 0
        config.reset()

    def test_set_seed(self):
        """Set seed property."""
        from oida.fuzz.core.mutation.config import MutationConfig

        config = MutationConfig()
        config.seed = 42
        assert config.seed == 42
        config.reset()

    def test_reset(self):
        """Reset restores defaults."""
        from oida.fuzz.core.mutation.config import MutationConfig

        config = MutationConfig()
        config.use_radamsa = True
        config.radamsa_mutation_count = 500
        config.seed = 42
        config.reset()
        assert config.use_radamsa is False
        assert config.radamsa_mutation_count == 200
        assert config.seed is None

    def test_is_radamsa_available(self):
        """is_radamsa_available always returns True."""
        from oida.fuzz.core.mutation.config import MutationConfig

        config = MutationConfig()
        assert config.is_radamsa_available() is True
        config.reset()


# =============================================================================
# Test Global Functions
# =============================================================================


class TestGlobalMutationFunctions:
    """Tests for global mutation functions."""

    def setup_method(self):
        """Reset global config before each test."""
        from oida.fuzz.core.mutation.config import get_mutation_config

        get_mutation_config().reset()

    def teardown_method(self):
        """Reset global config after each test."""
        from oida.fuzz.core.mutation.config import get_mutation_config

        get_mutation_config().reset()

    def test_enable_radamsa(self):
        """enable_radamsa enables global radamsa."""
        from oida.fuzz.core.mutation.config import (
            enable_radamsa,
            is_radamsa_enabled,
            get_radamsa_mutation_count,
        )

        enable_radamsa(300)
        assert is_radamsa_enabled() is True
        assert get_radamsa_mutation_count() == 300

    def test_disable_radamsa(self):
        """disable_radamsa disables global radamsa."""
        from oida.fuzz.core.mutation.config import (
            enable_radamsa,
            disable_radamsa,
            is_radamsa_enabled,
        )

        enable_radamsa()
        disable_radamsa()
        assert is_radamsa_enabled() is False

    def test_set_mutation_seed(self):
        """set_mutation_seed updates global seed."""
        from oida.fuzz.core.mutation.config import set_mutation_seed, get_mutation_seed

        set_mutation_seed(42)
        assert get_mutation_seed() == 42

    def test_get_mutation_config(self):
        """get_mutation_config returns the singleton."""
        from oida.fuzz.core.mutation.config import get_mutation_config, MutationConfig

        config = get_mutation_config()
        assert isinstance(config, MutationConfig)
