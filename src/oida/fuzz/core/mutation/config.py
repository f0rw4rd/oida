"""
Mutation configuration for OIDA fuzzer

This module provides both:
- Instance-level MutationStrategy for per-fuzzer configuration (recommended)
- Global MutationConfig singleton for backwards compatibility (deprecated)
"""

import threading
import warnings
from dataclasses import dataclass
from typing import Optional


@dataclass
class MutationStrategy:
    """
    Instance-level mutation configuration for a single fuzzer.

    Use this instead of global enable_radamsa()/disable_radamsa() to allow
    multiple fuzzers with different mutation strategies to run concurrently.

    Args:
        use_radamsa: Whether to use Radamsa-style mutations
        mutation_count: Number of mutations per field when using Radamsa

    Example:
        strategy = MutationStrategy(use_radamsa=True, mutation_count=500)
        fuzzer = ModbusFuzzer(config, mutation_strategy=strategy)
    """

    use_radamsa: bool = False
    mutation_count: int = 200

    def __post_init__(self):
        if self.mutation_count < 1:
            raise ValueError("Mutation count must be >= 1")

    @classmethod
    def from_config(cls, config) -> "MutationStrategy":
        """Create MutationStrategy from FuzzerConfig options."""
        return cls(
            use_radamsa=config.get_option("use_radamsa", False),
            mutation_count=config.get_option("radamsa_mutation_count", 200),
        )

    def is_radamsa_available(self) -> bool:
        """Check if radamsa-style mutations are available (always True with native impl)"""
        return True


class MutationConfig:
    """
    Global configuration for mutation strategies (deprecated).

    Prefer MutationStrategy for per-fuzzer, instance-level configuration.

    This singleton is retained for backwards compatibility. All reads and
    writes are protected by _lock to make concurrent access safe.
    """

    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self._use_radamsa = False
        self._radamsa_mutation_count = 200
        self._radamsa_available = None
        self._seed: Optional[int] = None
        self._initialized = True

    @property
    def use_radamsa(self) -> bool:
        """Whether to use Radamsa for mutations"""
        with self._lock:
            return self._use_radamsa

    @use_radamsa.setter
    def use_radamsa(self, value: bool):
        """Enable/disable Radamsa-style mutations (uses native implementation)"""
        with self._lock:
            self._use_radamsa = value

    @property
    def radamsa_mutation_count(self) -> int:
        """Number of mutations per field when using Radamsa"""
        with self._lock:
            return self._radamsa_mutation_count

    @radamsa_mutation_count.setter
    def radamsa_mutation_count(self, value: int):
        """Set mutation count for Radamsa"""
        if value < 1:
            raise ValueError("Mutation count must be >= 1")
        with self._lock:
            self._radamsa_mutation_count = value

    def is_radamsa_available(self) -> bool:
        """Check if radamsa-style mutations are available (always True with native impl)"""
        return True

    @property
    def seed(self) -> Optional[int]:
        """Global random seed for reproducible mutations"""
        with self._lock:
            return self._seed

    @seed.setter
    def seed(self, value: Optional[int]):
        """Set global random seed"""
        with self._lock:
            self._seed = value

    def reset(self):
        """Reset to default settings"""
        with self._lock:
            self._use_radamsa = False
            self._radamsa_mutation_count = 200
            self._seed = None


# Global singleton instance
_config = MutationConfig()


def enable_radamsa(mutation_count: int = 200):
    """
    Enable Radamsa mutations globally.

    .. deprecated::
        Use ``MutationStrategy(use_radamsa=True)`` per-fuzzer instead.

    Args:
        mutation_count: Number of mutations per field
    """
    warnings.warn(
        "enable_radamsa() is deprecated. Use MutationStrategy(use_radamsa=True) instead.",
        DeprecationWarning,
        stacklevel=2,
    )
    _config.use_radamsa = True
    _config.radamsa_mutation_count = mutation_count


def disable_radamsa():
    """
    Disable Radamsa mutations (use boofuzz defaults).

    .. deprecated::
        Use ``MutationStrategy(use_radamsa=False)`` per-fuzzer instead.
    """
    warnings.warn(
        "disable_radamsa() is deprecated. Use MutationStrategy(use_radamsa=False) instead.",
        DeprecationWarning,
        stacklevel=2,
    )
    _config.use_radamsa = False


def get_mutation_config() -> MutationConfig:
    """Get the global mutation configuration"""
    return _config


def is_radamsa_enabled() -> bool:
    """Check if Radamsa mutations are enabled"""
    return _config.use_radamsa


def get_radamsa_mutation_count() -> int:
    """Get the configured Radamsa mutation count"""
    return _config.radamsa_mutation_count


def set_mutation_seed(seed: Optional[int]):
    """Set the global random seed for reproducible mutations"""
    _config.seed = seed


def get_mutation_seed() -> Optional[int]:
    """Get the global random seed"""
    return _config.seed
