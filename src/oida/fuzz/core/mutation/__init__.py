"""Mutation engine for protocol fuzzing.

This module provides mutation primitives for fuzzing:
- Native Python radamsa-style mutations (default, no dependencies)
- Mutation configuration (singleton)
"""

from .config import (
    MutationConfig,
    MutationStrategy,
    enable_radamsa,
    disable_radamsa,
    is_radamsa_enabled,
    set_mutation_seed,
    get_mutation_seed,
)
from .radamsa import SeedLoader
from .radamsa_native import (
    NativeRadamsaMutator,
    get_native_mutator,
    INTERESTING_8,
    INTERESTING_16,
    INTERESTING_32,
    ASCII_NUMBERS,
)

# Alias for backwards compatibility - NativeRadamsaMutator is now the default
RadamsaMutator = NativeRadamsaMutator


def get_mutator(seed: int = None, prefer_native: bool = True):
    """
    Get a mutator instance.

    Args:
        seed: Random seed for reproducibility
        prefer_native: Ignored (kept for API compatibility). Always uses native.

    Returns:
        NativeRadamsaMutator instance
    """
    return NativeRadamsaMutator(seed=seed)


__all__ = [
    # Configuration
    "MutationConfig",
    "MutationStrategy",
    "enable_radamsa",
    "disable_radamsa",
    "is_radamsa_enabled",
    "set_mutation_seed",
    "get_mutation_seed",
    # Radamsa-style mutator (native Python implementation)
    "RadamsaMutator",  # Alias for NativeRadamsaMutator
    "SeedLoader",
    # Native Python mutator
    "NativeRadamsaMutator",
    "get_native_mutator",
    "get_mutator",
    # Interesting values for external use
    "INTERESTING_8",
    "INTERESTING_16",
    "INTERESTING_32",
    "ASCII_NUMBERS",
]
