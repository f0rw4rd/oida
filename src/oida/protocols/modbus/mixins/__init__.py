"""
Modbus Protocol Mixins

This package contains mixin classes that provide specific functionality
for the Modbus NXC connection class. Each mixin handles a logical group
of related operations.

Mixins:
    - IdentificationMixin: MEI device ID, Server ID, Exception Status (FC 7, 17, 43/14)
    - DiagnosticsMixin: Diagnostics operations (FC 8)
    - EventsMixin: Communication events (FC 11, 12)
    - FilesMixin: File record operations (FC 20, 21, 22, 23, 24)
    - WritesMixin: Write operations (FC 5, 6, 15, 16) and write testing
    - MonitorMixin: Register monitoring mode
    - FuzzMixin: Fuzzing operations for security testing
    - CANopenMixin: CANopen MEI operations (FC 43/13)
    - RawFCMixin: Custom/raw function code handling
    - SunSpecMixin: SunSpec runtime model discovery
"""

from .identification import IdentificationMixin
from .diagnostics import DiagnosticsMixin
from .events import EventsMixin
from .files import FilesMixin
from .writes import WritesMixin
from .monitor import MonitorMixin
from .fuzz import FuzzMixin
from .canopen import CANopenMixin
from .raw_fc import RawFCMixin
from .sunspec import SunSpecMixin
from .map_rw import MapReadWriteMixin

__all__ = [
    "IdentificationMixin",
    "DiagnosticsMixin",
    "EventsMixin",
    "FilesMixin",
    "WritesMixin",
    "MonitorMixin",
    "FuzzMixin",
    "CANopenMixin",
    "RawFCMixin",
    "SunSpecMixin",
    "MapReadWriteMixin",
]
