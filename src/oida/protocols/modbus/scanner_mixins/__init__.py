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

from oida.protocols.modbus.scanner_mixins.identification import ScannerIdentificationMixin
from oida.protocols.modbus.scanner_mixins.discovery import ScannerDiscoveryMixin
from oida.protocols.modbus.scanner_mixins.diagnostics import ScannerDiagnosticsMixin
from oida.protocols.modbus.scanner_mixins.comm_events import ScannerCommEventsMixin
from oida.protocols.modbus.scanner_mixins.file_ops import ScannerFileOpsMixin
from oida.protocols.modbus.scanner_mixins.write_ops import ScannerWriteOpsMixin
from oida.protocols.modbus.scanner_mixins.reporting import ScannerReportingMixin
from oida.protocols.modbus.scanner_mixins.custom_fc import ScannerCustomFCMixin

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
