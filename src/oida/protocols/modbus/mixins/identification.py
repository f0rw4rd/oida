"""
Modbus Identification Mixin

Handles device identification operations:
- MEI Device Identification (FC 43/14)
- Server ID (FC 17)
- Exception Status (FC 7)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


class IdentificationMixin(_ScannerBase):
    """Mixin providing Modbus device identification operations."""

    def _handle_identify(self):
        """Handle device identification (MEI)

        Supports --mei-object and --mei-object-id arguments:
        - --mei-object: "basic", "regular", "extended", "specific", or "all"
        - --mei-object-id: specific object ID (0x00-0xFF) for "specific" mode
        """
        mei_object = getattr(self.args, "mei_object", None)
        mei_object_id = getattr(self.args, "mei_object_id", None)

        # Show what we're reading
        if mei_object == "specific" and mei_object_id is not None:
            self.logger.display(f"Reading MEI object ID 0x{mei_object_id:02X} (specific mode)...")
        elif mei_object and mei_object != "all":
            self.logger.display(f"Reading device identification (MEI {mei_object})...")
        else:
            self.logger.display("Reading device identification (MEI)...")

        mei_info = self.scanner._read_device_identification(
            self.conn,
            mei_object=mei_object,
            mei_object_id=mei_object_id,
        )
        if mei_info:
            self.results["data"]["mei"] = mei_info
            self.logger.display("[MEI Device Identification]")
            for key, value in mei_info.items():
                self.logger.display(f"  {key}: {value}")
        else:
            self.logger.warning("[MEI] Device identification not supported")

    def _handle_server_id(self):
        """Handle Server ID query (FC 17)"""
        self.logger.display("Reading Server ID (FC 17)...")
        server_info = self.scanner.read_server_id(self.conn)
        if server_info:
            self.results["data"]["server_id"] = server_info
            self.logger.display("[Server ID (FC 17)]")

            # Show full identifier if available (e.g., "Pymodbus")
            if "identifier" in server_info:
                self.logger.display(f"  Identifier: {server_info['identifier']}")
            else:
                self.logger.display(f"  Server ID: {server_info.get('server_id_hex', 'N/A')}")

            self.logger.display(f"  Run Status: {server_info.get('run_status', 'Unknown')}")

            # Show raw hex for debugging
            if "identifier_hex" in server_info:
                self.logger.display(f"  Raw Identifier: {server_info['identifier_hex']}")
        else:
            self.logger.warning("[Server ID] FC 17 not supported by device")

    def _handle_exception_status(self):
        """Handle Exception Status query (FC 7)"""
        self.logger.display("Reading Exception Status (FC 7)...")
        status = self.scanner.read_exception_status(self.conn)
        if status is not None:
            self.results["data"]["exception_status"] = status
            self.logger.display("[Exception Status (FC 7)]")
            self.logger.display(f"  Status Byte: 0x{status:02X} ({status:08b})")
            # Show individual bits
            for i in range(8):
                bit_val = (status >> i) & 1
                self.logger.display(f"  Bit {i}: {bit_val}")
        else:
            self.logger.warning("[Exception Status] FC 7 not supported by device")
