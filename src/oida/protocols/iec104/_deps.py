"""
IEC 104 Dependency Management

Thread-safe lazy loading for c104 and pyserial dependencies.
"""

import threading

from ...utils.lazy_import import lazy_import

# Lazy import for c104 - only loads when actually used
_c104 = lazy_import("c104", "IEC 104")

# Lazy import for pyserial (IEC 101 serial mode, optional)
_serial = lazy_import("serial", "IEC 101", install_hint="pip install pyserial")

# Export for test compatibility
PYSERIAL_AVAILABLE = _serial.is_available


class _C104Cache:
    """Thread-safe singleton cache for c104 module.

    Avoids global keyword usage while providing module-level export
    for test compatibility.
    """

    _lock = threading.Lock()
    _module = None

    @classmethod
    def get(cls):
        """Get c104 module, raising DependencyError if not available."""
        if cls._module is not None:
            return cls._module
        with cls._lock:
            if cls._module is None:
                cls._module = _c104()
        return cls._module


# Module-level export for test compatibility
c104 = None


def _get_c104():
    """Get c104 module, raising DependencyError if not available."""
    import sys

    result = _C104Cache.get()
    # Update module-level export for test compatibility
    current_module = sys.modules[__name__]
    current_module.c104 = result
    return result
