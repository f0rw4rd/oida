"""PROFINET lazy imports and utility functions."""

from ...utils.lazy_import import lazy_import

import logging

logger = logging.getLogger(__name__)


# Lazy import for optional profinet-py dependency
_profinet = lazy_import("profinet", "PROFINET")


def get_indices_module():
    """Get profinet.indices module."""
    _profinet()  # raise DependencyError if profinet-py is not installed
    from profinet import indices

    return indices


def get_blocks_module():
    """Get profinet.blocks module."""
    _profinet()  # raise DependencyError if profinet-py is not installed
    from profinet import blocks

    return blocks


def get_alarms_module():
    """Get profinet.alarms module, or None if unavailable."""
    if not _profinet.is_available:
        return None
    try:
        from profinet import alarms

        return alarms
    except ImportError as e:
        logger.debug(f"Optional import alarms not available: {e}")
        return None
