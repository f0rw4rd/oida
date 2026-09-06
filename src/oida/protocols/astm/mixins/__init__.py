"""
ASTM/LIS Protocol Mixins

This package contains mixin classes that provide specific functionality
for the ASTM NXC connection class. Each mixin handles a logical group
of related operations.

Mixins:
    - FramingMixin: ENQ/ACK handshake, frame send/receive, checksums
    - RecordsMixin: Query, Patient, Order, Result record operations
    - EnumerationMixin: Test/instrument/patient enumeration, record type probing
    - SecurityMixin: Protocol fuzzing and security analysis
"""

from .framing import FramingMixin
from .records import RecordsMixin
from .enumeration import EnumerationMixin
from .security import SecurityMixin

__all__ = [
    "FramingMixin",
    "RecordsMixin",
    "EnumerationMixin",
    "SecurityMixin",
]
