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

from oida.protocols.astm.mixins.framing import FramingMixin
from oida.protocols.astm.mixins.records import RecordsMixin
from oida.protocols.astm.mixins.enumeration import EnumerationMixin
from oida.protocols.astm.mixins.security import SecurityMixin

__all__ = [
    "FramingMixin",
    "RecordsMixin",
    "EnumerationMixin",
    "SecurityMixin",
]
