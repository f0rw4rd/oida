"""
Modbus Scanner Mixins

Mixin classes that provide specific functionality groups for ModbusScanner.
These are separate from the NXC connection mixins in ``mixins/``.

Mixins:
    - ScannerIdentificationMixin: Device ID, Server ID, MEI (FC 7, 17, 43/14)
    - ScannerDiscoveryMixin: Unit discovery and function code enumeration
    - ScannerDiagnosticsMixin: FC 8 diagnostics (echo, counters, register)
    - ScannerCommEventsMixin: FC 11/12 communication events
    - ScannerFileOpsMixin: FC 20-24 file/FIFO/mask/atomic operations
    - ScannerWriteOpsMixin: Write operations and write-access scanning
    - ScannerReportingMixin: Register decoding, monitoring, and reporting
    - ScannerCustomFCMixin: Custom/raw function code handling
"""

from .identification import ScannerIdentificationMixin
from .discovery import ScannerDiscoveryMixin
from .diagnostics import ScannerDiagnosticsMixin
from .comm_events import ScannerCommEventsMixin
from .file_ops import ScannerFileOpsMixin
from .write_ops import ScannerWriteOpsMixin
from .reporting import ScannerReportingMixin
from .custom_fc import ScannerCustomFCMixin

__all__ = [
    "ScannerIdentificationMixin",
    "ScannerDiscoveryMixin",
    "ScannerDiagnosticsMixin",
    "ScannerCommEventsMixin",
    "ScannerFileOpsMixin",
    "ScannerWriteOpsMixin",
    "ScannerReportingMixin",
    "ScannerCustomFCMixin",
]
