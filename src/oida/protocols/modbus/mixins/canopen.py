"""
Modbus CANopen Mixin

Handles CANopen MEI operations (FC 43/13 - CiA 309-2):
- CANopen gateway info
- SDO read (upload)
- SDO write (download)
"""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING, Any, Optional, Tuple

from ..constants import CANopenMEICommand, CANOPEN_DATA_TYPES, CANOPEN_COMMON_OBJECTS

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
        request_data = bytes([0x01])  # GET_INFO command

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
        if not getattr(self.args, "confirm", False):
            self.logger.fail("--canopen-write requires --confirm flag")
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
            return node_id, index, subindex
        except ValueError as e:
            self.logger.debug(f"Failed to get node_id: {e}")
            return None, 0, 0

    def _decode_canopen_value(self, data: bytes, data_type: int) -> Any:
        """Decode CANopen value based on data type."""
        if not data:
            return None

        type_info = CANOPEN_DATA_TYPES.get(data_type)
        if not type_info:
            return data.hex()

        type_name, size = type_info

        try:
            if type_name == "BOOLEAN":
                return bool(data[0])
            elif type_name in ("INTEGER8", "UNSIGNED8"):
                return data[0]
            elif type_name == "INTEGER16":
                return struct.unpack("<h", data[:2])[0]
            elif type_name == "UNSIGNED16":
                return struct.unpack("<H", data[:2])[0]
            elif type_name == "INTEGER32":
                return struct.unpack("<i", data[:4])[0]
            elif type_name == "UNSIGNED32":
                return struct.unpack("<I", data[:4])[0]
            elif type_name == "REAL32":
                return struct.unpack("<f", data[:4])[0]
            elif type_name == "REAL64":
                return struct.unpack("<d", data[:8])[0]
            elif type_name in ("VISIBLE_STRING", "OCTET_STRING"):
                return data.decode("utf-8", errors="replace").rstrip("\x00")
            else:
                return data.hex()
        except Exception:
            return data.hex()
