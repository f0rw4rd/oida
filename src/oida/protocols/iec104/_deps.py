"""
IEC 104 Dependency Management

Thread-safe lazy loading for c104 and pyserial dependencies.
"""

from oida.utils.lazy_import import lazy_import

# Lazy import for c104 - only loads when actually used
_c104 = lazy_import("c104", "IEC 104")

# Lazy import for pyserial (IEC 101 serial mode, optional)
_serial = lazy_import("serial", "IEC 101", install_hint="pip install oida-ics[serial]")

# Export for test compatibility
PYSERIAL_AVAILABLE = _serial.is_available

# Patch target for tests (``@patch("oida.protocols.iec104.c104")``). Not read
# by production code, which always loads the module via ``_get_c104()``.
c104 = None


def _get_c104():
    """Get the c104 module, raising DependencyError if not available.

    ``lazy_import`` already caches and locks the underlying module load.
    """
    return _c104()
