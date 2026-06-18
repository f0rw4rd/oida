"""
BACnet Protocol Scanner

Scans BACnet/IP (Building Automation and Control Network) endpoints for:
- Device discovery via Who-Is/I-Am broadcast
- Object enumeration (analog/binary/multistate inputs/outputs/values)
- Property reading and writing
- Schedule and trend log enumeration
- Security assessment (anonymous access, writable properties)
- Object state dumps and comparisons

BACnet is commonly used in building automation for:
- HVAC control (heating, ventilation, air conditioning)
- Lighting control
- Fire detection and alarm systems
- Access control and security systems
- Energy management

WARNING: BACnet has NO built-in authentication or encryption by default.
Most devices allow anonymous read/write access to all properties.

CLI examples:
    oida bacnet 192.168.1.0/24 --who-is            # Discover devices
    oida bacnet 192.168.1.100 --identify           # Device identification
    oida bacnet 192.168.1.100 --enumerate-objects  # List all objects
    oida bacnet 192.168.1.100 --dump -o backup     # Full object dump
    oida bacnet 192.168.1.100 --assess             # Security assessment
    oida bacnet 192.168.1.100 --monitor            # Monitor values
"""

# Re-export the NXC-style connection class (mixin-based)
from .nxc_connection import bacnet

# Re-export constants used by tests and external code
from .constants import (
    _is_bac0_available,
    CONTROL_POINT_TYPES,
    OBJECT_TYPE_NAMES,
    OBJECT_TYPES,
    VENDORS,
)

__all__ = [
    "bacnet",
    "OBJECT_TYPES",
    "OBJECT_TYPE_NAMES",
    "CONTROL_POINT_TYPES",
    "VENDORS",
    "BAC0_AVAILABLE",
]


def __getattr__(name: str):
    """Module-level lazy attribute access for deferred imports."""
    if name == "BAC0_AVAILABLE":
        # Return BAC0 availability lazily to avoid importing at module load
        return _is_bac0_available()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
