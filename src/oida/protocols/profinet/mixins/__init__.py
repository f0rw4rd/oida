"""
PROFINET Protocol Mixins

This package contains mixin classes that provide specific functionality
for the PROFINET NXC connection class. Each mixin handles a logical group
of related operations.

Mixins:
    - RPCMixin: RPC read operations (I&M data, diagnosis, AR data, slot discovery)
    - EnumerationMixin: Index enumeration (smart probe, full scan, GSDML-based)
    - FuzzMixin: Security fuzzing of writable indices
    - CyclicMixin: Cyclic IO test (IOCR establishment, frame exchange)
"""

from oida.protocols.profinet.mixins.cyclic import CyclicMixin
from oida.protocols.profinet.mixins.enumeration import EnumerationMixin
from oida.protocols.profinet.mixins.fuzz import FuzzMixin
from oida.protocols.profinet.mixins.rpc import RPCMixin

__all__ = [
    "RPCMixin",
    "EnumerationMixin",
    "FuzzMixin",
    "CyclicMixin",
]
