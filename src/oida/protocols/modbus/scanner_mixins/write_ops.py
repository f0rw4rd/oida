"""
Modbus Scanner Write Operations Mixin

Handles write operations and write-access scanning:
- Safe write (write same value back)
- Multiple registers/coils write (FC 15, 16)
- Write-access scanning
"""

from __future__ import annotations

from typing import Any, Dict, List, TYPE_CHECKING

if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


class ScannerWriteOpsMixin(_ScannerBase):
    """Mixin providing write operations and write-access scanning for ModbusScanner."""

    def _write_register_safe(
        self,
        client: Any,
        address: int,
        value: int,
        register_type: str = "holding",
        restore_on_exit: bool = True,
    ) -> Dict[str, Any]:
        """
        Write to register with safety checks

        Args:
            client: Modbus client
            address: Register address
            value: Value to write
            register_type: 'holding' or 'coil'
            restore_on_exit: Restore original value after test

        Returns:
            dict: Write result with original value
        """
        result = {
            "success": False,
            "address": address,
            "value_written": value,
            "original_value": None,
            "restored": False,
        }

        try:
            # pymodbus 3.8+ uses count=/device_id= instead of positional/unit=
            # Read original value
            if register_type == "holding":
                read_result = client.read_holding_registers(
                    address, count=1, device_id=self.unit_id
                )
                if not read_result.isError():
                    result["original_value"] = read_result.registers[0]

                # Write new value
                write_result = client.write_register(address, value, device_id=self.unit_id)
                result["success"] = not write_result.isError()

                # Restore if requested
                if restore_on_exit and result["original_value"] is not None:
                    restore_result = client.write_register(
                        address, result["original_value"], device_id=self.unit_id
                    )
                    result["restored"] = not restore_result.isError()
                    if not result["restored"]:
                        result["error"] = "Restore write failed; register left modified"
                        self.logger.warning(
                            f"Failed to restore register {address}; device left holding test value"
                        )

            elif register_type == "coil":
                read_result = client.read_coils(address, count=1, device_id=self.unit_id)
                if not read_result.isError():
                    result["original_value"] = read_result.bits[0]

                # Write new value (convert to bool)
                write_result = client.write_coil(address, bool(value), device_id=self.unit_id)
                result["success"] = not write_result.isError()

                # Restore if requested
                if restore_on_exit and result["original_value"] is not None:
                    restore_result = client.write_coil(
                        address, result["original_value"], device_id=self.unit_id
                    )
                    result["restored"] = not restore_result.isError()
                    if not result["restored"]:
                        result["error"] = "Restore write failed; coil left modified"
                        self.logger.warning(
                            f"Failed to restore coil {address}; device left holding test value"
                        )

        except Exception as e:
            self.logger.debug("write register safe failed: %s", e)
            result["error"] = str(e)
            self.logger.fail(f"Write failed: {e}")

        return result

    def _write_multiple_registers(
        self,
        client: Any,
        address: int,
        values: List[int],
        restore_on_exit: bool = True,
    ) -> Dict[str, Any]:
        """
        Write multiple registers (FC 16)

        Args:
            client: Modbus client
            address: Starting register address
            values: List of values to write
            restore_on_exit: Restore original values after write

        Returns:
            dict: Write result
        """
        result = {
            "success": False,
            "address": address,
            "count": len(values),
            "values_written": values,
            "original_values": None,
            "restored": False,
        }

        try:
            # pymodbus 3.8+ uses count=/device_id= instead of positional/unit=
            # Read original values
            read_result = client.read_holding_registers(
                address, count=len(values), device_id=self.unit_id
            )
            if not read_result.isError():
                result["original_values"] = list(read_result.registers)

            # Write multiple registers
            write_result = client.write_registers(address, values, device_id=self.unit_id)
            result["success"] = not write_result.isError()

            # Restore if requested
            if restore_on_exit and result["original_values"]:
                restore_result = client.write_registers(
                    address, result["original_values"], device_id=self.unit_id
                )
                result["restored"] = not restore_result.isError()
                if not result["restored"]:
                    result["error"] = "Restore write failed; registers left modified"
                    self.logger.warning(
                        f"Failed to restore registers at {address}; device left holding test values"
                    )

        except Exception as e:
            self.logger.debug("write multiple registers failed: %s", e)
            result["error"] = str(e)
            self.logger.fail(f"Write multiple registers failed: {e}")

        return result

    def _write_multiple_coils(
        self,
        client: Any,
        address: int,
        values: List[bool],
        restore_on_exit: bool = True,
    ) -> Dict[str, Any]:
        """
        Write multiple coils (FC 15)

        Args:
            client: Modbus client
            address: Starting coil address
            values: List of boolean values to write
            restore_on_exit: Restore original values after write

        Returns:
            dict: Write result
        """
        result = {
            "success": False,
            "address": address,
            "count": len(values),
            "values_written": values,
            "original_values": None,
            "restored": False,
        }

        try:
            # pymodbus 3.8+ uses count=/device_id= instead of positional/unit=
            # Read original values
            read_result = client.read_coils(address, count=len(values), device_id=self.unit_id)
            if not read_result.isError():
                result["original_values"] = list(read_result.bits[: len(values)])

            # Write multiple coils
            write_result = client.write_coils(address, values, device_id=self.unit_id)
            result["success"] = not write_result.isError()

            # Restore if requested
            if restore_on_exit and result["original_values"]:
                restore_result = client.write_coils(
                    address, result["original_values"], device_id=self.unit_id
                )
                result["restored"] = not restore_result.isError()
                if not result["restored"]:
                    result["error"] = "Restore write failed; coils left modified"
                    self.logger.warning(
                        f"Failed to restore coils at {address}; device left holding test values"
                    )

        except Exception as e:
            self.logger.debug("write multiple coils failed: %s", e)
            result["error"] = str(e)
            self.logger.fail(f"Write multiple coils failed: {e}")

        return result

    def _scan_write_access(
        self,
        client: Any,
        addresses: List[int],
        register_type: str = "holding_registers",
        mode: str = "safe",
    ) -> Dict[str, Any]:
        """
        Scan a range of registers for write access

        Args:
            client: Modbus client
            addresses: List of addresses to test
            register_type: 'holding_registers' or 'coils'
            mode: 'safe' (write same value) or 'destructive' (write different value)

        Returns:
            dict: {writable: [...], read_only: [...], errors: [...]}
        """
        from ..register_io import read_registers_batched

        results = {
            "writable": [],
            "read_only": [],
            "errors": [],
            "mode": mode,
            "register_type": register_type,
        }

        # Batch-read current values for all addresses first.
        current_values = read_registers_batched(
            client,
            register_type,
            addresses,
            unit_id=self.unit_id,
            fallback_individual=True,
            logger=self.logger,
        )

        for addr in addresses:
            if addr not in current_values:
                results["errors"].append({"address": addr, "error": "Read failed"})
                continue

            current_value = current_values[addr]

            try:
                if mode == "safe":
                    test_result = self._test_write_access_safe(
                        client, register_type, addr, current_value
                    )
                else:
                    test_result = self._test_write_access_destructive(
                        client, register_type, addr, current_value
                    )

                if test_result.get("writable"):
                    results["writable"].append(
                        {
                            "address": addr,
                            "value": current_value,
                            "details": test_result,
                        }
                    )
                else:
                    results["read_only"].append(
                        {
                            "address": addr,
                            "value": current_value,
                            "error": test_result.get("error"),
                        }
                    )

            except Exception as e:
                self.logger.debug("scan write access failed: %s", e)
                results["errors"].append({"address": addr, "error": str(e)})

        return results
