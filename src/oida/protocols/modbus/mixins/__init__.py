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

from oida.protocols.modbus.mixins.identification import IdentificationMixin
from oida.protocols.modbus.mixins.diagnostics import DiagnosticsMixin
from oida.protocols.modbus.mixins.events import EventsMixin
from oida.protocols.modbus.mixins.files import FilesMixin
from oida.protocols.modbus.mixins.writes import WritesMixin
from oida.protocols.modbus.mixins.monitor import MonitorMixin
from oida.protocols.modbus.mixins.fuzz import FuzzMixin
from oida.protocols.modbus.mixins.canopen import CANopenMixin
from oida.protocols.modbus.mixins.raw_function_codes import RawFCMixin
from oida.protocols.modbus.mixins.sunspec import SunSpecMixin
from oida.protocols.modbus.mixins.read_write import MapReadWriteMixin

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
