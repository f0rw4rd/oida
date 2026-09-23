"""
Modbus Scanner File Operations Mixin

Handles advanced Modbus function codes:
- Read File Record (FC 20)
- Write File Record (FC 21)
- Mask Write Register (FC 22)
- Read/Write Multiple Registers (FC 23)
- Read FIFO Queue (FC 24)
"""

from __future__ import annotations

import struct
from typing import Any, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


class ScannerFileOpsMixin(_ScannerBase):
    """Mixin providing FC 20-24 file/FIFO/mask/atomic operations for ModbusScanner."""

    def _read_file_record(
        self, client: Any, file_number: int, record_number: int, record_length: int = 1
    ) -> Optional[Dict[str, Any]]:
        """
        Read file record (FC 20)

        Args:
            client: Modbus client
            file_number: File number (1-65535)
            record_number: Record number (0-9999)
            record_length: Number of registers to read

        Returns:
            dict: File record data or None
        """
        from oida.protocols.modbus.scanner import _get_file_record_classes

        try:
            # Use pymodbus built-in read_file_record method
            FileRecord, _, _ = _get_file_record_classes()
            records = [
                FileRecord(
                    file_number=file_number,
                    record_number=record_number,
                    record_length=record_length,
                )
            ]
            result = client.read_file_record(records=records, device_id=self.unit_id)
            if not result.isError():
                # Extract record data from response
                record_data = []
                if hasattr(result, "records") and result.records:
                    for rec in result.records:
                        # pymodbus FileRecord always carries record_data.
                        data = rec.record_data
                        registers = []
                        for i in range(0, len(data), 2):
                            if i + 1 < len(data):
                                registers.append(struct.unpack(">H", data[i : i + 2])[0])
                        record_data.append(registers)
                return {
                    "file_number": file_number,
                    "record_number": record_number,
                    "data": record_data,
                }
        except Exception as e:
            self.logger.debug(f"File read failed: {e}")
        return None

    def _write_file_record(
        self, client: Any, file_number: int, record_number: int, data: bytes
    ) -> Dict[str, Any]:
        """
        Write file record (FC 21)

        Args:
            client: Modbus client
            file_number: File number (1-65535)
            record_number: Record number (0-9999)
            data: Data bytes to write (must be even length, as registers)

        Returns:
            dict: Write result with success status
        """
        from oida.protocols.modbus.scanner import _get_file_record_classes

        write_result = {
            "success": False,
            "file_number": file_number,
            "record_number": record_number,
            "bytes_written": 0,
        }

        try:
            # Use pymodbus built-in write_file_record method
            FileRecord, _, _ = _get_file_record_classes()

            # Pad data to even length if needed
            if len(data) % 2 != 0:
                data = data + b"\x00"

            records = [
                FileRecord(
                    file_number=file_number,
                    record_number=record_number,
                    record_data=data,
                )
            ]
            response = client.write_file_record(records=records, device_id=self.unit_id)
            if not response.isError():
                write_result["success"] = True
                write_result["bytes_written"] = len(data)
                write_result["registers_written"] = len(data) // 2
            else:
                write_result["error"] = f"Modbus error: {response}"

        except Exception as e:
            write_result["error"] = str(e)
            self.logger.debug(f"File write failed: {e}")

        return write_result

    def _mask_write_register(
        self, client: Any, address: int, and_mask: int, or_mask: int
    ) -> Dict[str, Any]:
        """
        Mask write register (FC 22)

        The register value is modified according to:
        Result = (Current AND And_Mask) OR (Or_Mask AND (NOT And_Mask))

        Args:
            client: Modbus client
            address: Register address
            and_mask: AND mask (16-bit)
            or_mask: OR mask (16-bit)

        Returns:
            dict: Operation result with success status
        """
        result = {
            "success": False,
            "address": address,
            "and_mask": and_mask,
            "or_mask": or_mask,
        }

        try:
            response = client.mask_write_register(
                address=address, and_mask=and_mask, or_mask=or_mask, device_id=self.unit_id
            )

            if not response.isError():
                result["success"] = True
                # Try to read back the new value for verification
                try:
                    read_response = client.read_holding_registers(
                        address=address, count=1, device_id=self.unit_id
                    )
                    if not read_response.isError():
                        result["new_value"] = read_response.registers[0]
                except Exception as e:
                    self.logger.debug(f"Verification read failed: {e}")
            else:
                result["error"] = f"Modbus error: {response}"

        except Exception as e:
            result["error"] = str(e)
            self.logger.debug(f"Mask write failed: {e}")

        return result

    def _atomic_read_write(
        self,
        client: Any,
        read_addr: int,
        read_count: int,
        write_addr: int,
        write_data: List[int],
    ) -> Dict[str, Any]:
        """
        Atomic read/write multiple registers (FC 23)

        Performs a read and write in a single atomic transaction.
        This is useful when you need to ensure consistency between
        reading and writing without other operations interfering.

        Args:
            client: Modbus client
            read_addr: Starting address for read
            read_count: Number of registers to read
            write_addr: Starting address for write
            write_data: List of register values to write

        Returns:
            dict: Operation result with read values and write confirmation
        """
        result = {
            "success": False,
            "read_address": read_addr,
            "read_count": read_count,
            "write_address": write_addr,
            "write_count": len(write_data),
            "read_values": [],
            "values_written": write_data,
        }

        try:
            response = client.readwrite_registers(
                read_address=read_addr,
                read_count=read_count,
                write_address=write_addr,
                values=write_data,
                device_id=self.unit_id,
            )

            if not response.isError():
                result["success"] = True
                # Extract read registers from response
                if hasattr(response, "registers"):
                    result["read_values"] = list(response.registers)
            else:
                result["error"] = f"Modbus error: {response}"

        except Exception as e:
            result["error"] = str(e)
            self.logger.debug(f"Atomic read/write failed: {e}")

        return result

    def _read_fifo_queue(self, client: Any, pointer_address: int) -> Optional[Dict[str, Any]]:
        """
        Read FIFO queue (FC 24)

        Args:
            client: Modbus client
            pointer_address: FIFO pointer address

        Returns:
            dict: FIFO queue data or None
        """
        from oida.protocols.modbus.scanner import GenericPDU, execute_pdu

        try:
            pdu = GenericPDU(function_code=24)
            # Encode pointer address
            pdu.encode = lambda: struct.pack(">H", pointer_address)
            result = execute_pdu(client, pdu, self.unit_id)
            if not result.isError():
                return {
                    "pointer_address": pointer_address,
                    "count": getattr(result, "count", 0),
                    "values": list(getattr(result, "values", [])),
                }
        except Exception as e:
            self.logger.debug(f"FIFO read failed: {e}")
        return None
