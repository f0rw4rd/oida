"""
Modbus CANopen Mixin

Handles CANopen MEI operations (FC 43/13 - CiA 309-2):
- CANopen gateway info
- SDO read (upload)
- SDO write (download)
"""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING, Optional, Tuple

from oida.protocols.modbus.constants import CANopenMEICommand, CANOPEN_COMMON_OBJECTS

if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


class CANopenMixin(_ScannerBase):
    """Mixin providing Modbus CANopen MEI operations."""

    def _handle_canopen_info(self):
        """Handle --canopen-info flag."""
        self.logger.display("Reading CANopen gateway info (FC 43/13)...")

        # Build MEI request for gateway info
        # FC 43, MEI Type 13, Command 0x01 (Get Info)
        request_data = bytes([CANopenMEICommand.GET_INFO])

        result = self.scanner._send_mei_canopen(self.conn, request_data)

        if result:
            self.results["data"]["canopen_info"] = result
            self.logger.display("  CANopen Gateway Info:")
            for key, value in result.items():
                self.logger.display(f"    {key}: {value}")
        else:
            self.logger.warning("CANopen MEI not supported or failed")

    def _handle_canopen_read(self):
        """Handle --canopen-read flag for SDO upload."""
        read_spec = getattr(self.args, "canopen_read", None)
        if not read_spec:
            return

        # Parse node:index:subindex
        node_id, index, subindex = self._parse_canopen_spec(read_spec)
        if node_id is None:
            self.logger.fail(
                "Invalid canopen-read format. Use: node:index:subindex (e.g., 1:0x1000:0)"
            )
            return

        self.logger.display(
            f"CANopen SDO Read: node={node_id}, index=0x{index:04X}, subindex={subindex}"
        )

        # Build SDO upload request
        # MEI Type 13, Command 0x40 (SDO Upload), then node/index/subindex
        request_data = bytes(
            [CANopenMEICommand.SDO_UPLOAD, node_id, index & 0xFF, (index >> 8) & 0xFF, subindex]
        )

        result = self.scanner._send_mei_canopen(self.conn, request_data)

        if result:
            self.results["data"]["canopen_read"] = result

            # Decode value if we know the object
            obj_name = CANOPEN_COMMON_OBJECTS.get(
                (index, subindex), f"Object 0x{index:04X}:{subindex}"
            )
            value = result.get("value", result.get("data"))

            self.logger.success(f"  {obj_name}: {value}")
        else:
            self.logger.fail("CANopen SDO read failed")

    def _handle_canopen_write(self):
        """Handle --canopen-write flag for SDO download."""
        if not self.require_confirm(
            "--canopen-write", detail="--canopen-write requires --confirm flag"
        ):
            self.results["success"] = False
            self.results["data"]["refused"] = "--canopen-write requires --confirm"
            return

        write_spec = getattr(self.args, "canopen_write", None)
        if not write_spec:
            return

        # Parse node:index:subindex=value
        if "=" not in write_spec:
            self.logger.fail("Invalid canopen-write format. Use: node:index:subindex=value")
            return

        spec_part, value_str = write_spec.rsplit("=", 1)
        node_id, index, subindex = self._parse_canopen_spec(spec_part)

        if node_id is None:
            self.logger.fail("Invalid canopen-write format")
            return

        # Parse value (hex or decimal)
        try:
            if value_str.startswith("0x"):
                value = int(value_str, 16)
            else:
                value = int(value_str)
        except ValueError:
            # Try as string
            value = value_str

        self.logger.display(
            f"CANopen SDO Write: node={node_id}, index=0x{index:04X}, subindex={subindex}, value={value}"
        )

        # Build SDO download request
        # MEI Type 13, Command 0x20 (SDO Download), node/index/subindex, then value
        if isinstance(value, int):
            value_bytes = struct.pack("<I", value)  # Little-endian 32-bit
        else:
            value_bytes = value.encode("utf-8")

        request_data = (
            bytes(
                [
                    CANopenMEICommand.SDO_DOWNLOAD,
                    node_id,
                    index & 0xFF,
                    (index >> 8) & 0xFF,
                    subindex,
                    len(value_bytes),
                ]
            )
            + value_bytes
        )

        result = self.scanner._send_mei_canopen(self.conn, request_data)

        if result and not result.get("error"):
            self.logger.success("CANopen SDO write successful")
            self.results["data"]["canopen_write"] = {"success": True, "value": value}
        elif result is None:
            self.logger.fail("CANopen SDO write failed: no response (CANopen MEI not supported?)")
        else:
            self.logger.fail(f"CANopen SDO write failed: {result.get('error', 'Unknown error')}")

    def _parse_canopen_spec(self, spec: str) -> Tuple[Optional[int], int, int]:
        """Parse CANopen node:index:subindex specification."""
        parts = spec.split(":")
        if len(parts) != 3:
            return None, 0, 0

        try:
            node_id = int(parts[0], 0)
            index = int(parts[1], 0)
            subindex = int(parts[2], 0)
            # node_id and subindex are packed into single bytes downstream, and
            # index into two; a caller like `300:0x1000:0` would otherwise raise
            # `bytes must be in range(0, 256)` outside the handler's try/except
            # and abort the run instead of the intended clean fail.
            if not (0 <= node_id <= 255):
                self.logger.debug(f"CANopen node_id out of range (0-255): {node_id}")
                return None, 0, 0
            if not (0 <= subindex <= 255):
                self.logger.debug(f"CANopen subindex out of range (0-255): {subindex}")
                return None, 0, 0
            if not (0 <= index <= 0xFFFF):
                self.logger.debug(f"CANopen index out of range (0-0xFFFF): {index}")
                return None, 0, 0
            return node_id, index, subindex
        except ValueError as e:
            self.logger.debug(f"Failed to get node_id: {e}")
            return None, 0, 0
