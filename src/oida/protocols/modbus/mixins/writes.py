"""
Modbus Writes Mixin

Handles write operations:
- Write Single Coil (FC 5)
- Write Single Register (FC 6)
- Write Multiple Coils (FC 15)
- Write Multiple Registers (FC 16)
- Write access testing
- Broadcast writes
"""

from __future__ import annotations

from ..decoder import ModbusEncoder, parse_endian
from ....utils.protocol_helpers import ProtocolParser

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


class WritesMixin(_ScannerBase):
    """Mixin providing Modbus write operations."""

    def _handle_write(self):
        """Handle write operation

        Supports typed encoding when -d/--decode is specified:
            --write 100=3.14159 -d f32    # Write float32 to regs 100-101
            --write 100=-1000000 -d i32   # Write int32 to regs 100-101
            --write 100="Test" -d str     # Write string to registers
            --write 100=DEADBEEF -d hex   # Write hex bytes
        """
        write_spec = getattr(self.args, "write", None)
        if not write_spec:
            return

        try:
            addr_str, value_str = write_spec.split("=", 1)  # Split only on first =
            address = int(addr_str)
        except ValueError:
            self.logger.fail(f"Invalid write spec: {write_spec} (use ADDR=VALUE)")
            return

        # Check if typed encoding is requested
        if self.decode_type:
            try:
                byte_order, word_order = parse_endian(self.endian)
                encoder = ModbusEncoder(byte_order=byte_order, word_order=word_order)
                string_length = getattr(self.args, "decode_width", None)
                registers = encoder.encode(value_str, self.decode_type, length=string_length)
                display_value = f"{value_str} ({self.decode_type})"
            except (ValueError, TypeError) as e:
                self.logger.fail(f"Failed to encode '{value_str}' as {self.decode_type}: {e}")
                return
        else:
            # Legacy behavior: raw integer
            try:
                value = int(value_str)
                registers = [value]
                display_value = str(value)
            except ValueError:
                self.logger.fail(
                    f"Invalid integer value: {value_str} (use -d TYPE for typed values)"
                )
                return

        # Check for confirmation
        if not getattr(self.args, "confirm", False):
            self.logger.fail("Write operation requires --confirm flag")
            if len(registers) == 1:
                self.logger.display(f"    Would write {display_value} to register {address}")
            else:
                self.logger.display(
                    f"    Would write {display_value} to registers {address}-{address + len(registers) - 1}"
                )
                self.logger.display(f"    Register values: {[hex(r) for r in registers]}")
            return

        # Perform write
        if self.broadcast_mode:
            # Broadcast mode: write without expecting response
            self._handle_broadcast_write(address, registers, display_value)
        elif len(registers) == 1:
            self.logger.display(f"Writing {display_value} to register {address}...")
            result = self.scanner._write_register_safe(
                self.conn,
                address,
                registers[0],
                restore_on_exit=getattr(self.args, "restore_on_exit", False),
            )
            self.results["data"]["write"] = result

            if result.get("success"):
                self.logger.success(f"[Write] {display_value} written to {address}")
                if result.get("restored"):
                    self.logger.display(f"  Original value {result.get('original_value')} restored")
            else:
                self.logger.fail(f"[Write] Failed: {result.get('error', 'Unknown error')}")
        else:
            self.logger.display(
                f"Writing {display_value} to registers {address}-{address + len(registers) - 1}..."
            )
            result = self.scanner._write_multiple_registers(
                self.conn,
                address,
                registers,
                restore_on_exit=getattr(self.args, "restore_on_exit", False),
            )
            self.results["data"]["write"] = result

            if result.get("success"):
                self.logger.success(
                    f"[Write] {display_value} written to {address}-{address + len(registers) - 1}"
                )
                if result.get("restored"):
                    self.logger.display(
                        f"  Original value(s) {result.get('original_values')} restored"
                    )
            else:
                self.logger.fail(f"[Write] Failed: {result.get('error', 'Unknown error')}")

    def _handle_broadcast_write(self, address: int, registers: list, display_value: str):
        """Handle broadcast write (unit ID 0) - no response expected."""
        unit_id = 0  # Broadcast address
        try:
            if len(registers) == 1:
                self.logger.display(f"[Broadcast] Writing {display_value} to register {address}...")
                self.conn.write_register(address, registers[0], device_id=unit_id)
            else:
                self.logger.display(
                    f"[Broadcast] Writing {display_value} to registers {address}-{address + len(registers) - 1}..."
                )
                self.conn.write_registers(address, registers, device_id=unit_id)

            # In broadcast mode we don't get a response, so we assume success
            self.logger.success("[Broadcast] Write sent (no confirmation possible)")
            self.results["data"]["broadcast_write"] = {
                "address": address,
                "values": registers,
                "display_value": display_value,
                "broadcast": True,
            }
        except Exception as e:
            self.logger.fail(f"[Broadcast] Write failed: {e}")
            self.results["data"]["broadcast_write"] = {
                "address": address,
                "values": registers,
                "error": str(e),
            }

    def _handle_broadcast_write_coil(self, address: int, value: bool):
        """Handle broadcast coil write (unit ID 0) - no response expected."""
        unit_id = 0  # Broadcast address
        try:
            self.logger.display(
                f"[Broadcast] Writing {'ON' if value else 'OFF'} to coil {address}..."
            )
            self.conn.write_coil(address, value, device_id=unit_id)
            self.logger.success("[Broadcast] Coil write sent (no confirmation possible)")
            self.results["data"]["broadcast_write_coil"] = {
                "address": address,
                "value": value,
                "broadcast": True,
            }
        except Exception as e:
            self.logger.fail(f"[Broadcast] Coil write failed: {e}")
            self.results["data"]["broadcast_write_coil"] = {
                "address": address,
                "value": value,
                "error": str(e),
            }

    def _handle_broadcast_write_multiple_coils(self, address: int, values: list):
        """Handle broadcast multiple coils write (unit ID 0) - no response expected."""
        unit_id = 0  # Broadcast address
        try:
            self.logger.display(f"[Broadcast] Writing {len(values)} coils starting at {address}...")
            self.conn.write_coils(address, values, device_id=unit_id)
            self.logger.success("[Broadcast] Multiple coils write sent (no confirmation possible)")
            self.results["data"]["broadcast_write_multiple_coils"] = {
                "address": address,
                "values": values,
                "count": len(values),
                "broadcast": True,
            }
        except Exception as e:
            self.logger.fail(f"[Broadcast] Multiple coils write failed: {e}")
            self.results["data"]["broadcast_write_multiple_coils"] = {
                "address": address,
                "values": values,
                "error": str(e),
            }

    def _handle_write_coil(self):
        """Handle write coil operation (FC 5)"""
        write_spec = getattr(self.args, "write_coil", None)
        if not write_spec:
            return

        try:
            addr_str, value_str = write_spec.split("=")
            address = int(addr_str)
            value = int(value_str)
            if value not in (0, 1):
                raise ValueError("Coil value must be 0 or 1")
        except ValueError as e:
            self.logger.fail(f"Invalid write-coil spec: {write_spec} (use ADDR=0|1): {e}")
            return

        if not getattr(self.args, "confirm", False):
            self.logger.fail("Write coil requires --confirm flag")
            self.logger.display(f"    Would write {value} to coil {address}")
            return

        if self.broadcast_mode:
            self._handle_broadcast_write_coil(address, bool(value))
        else:
            self.logger.display(f"Writing {value} to coil {address}...")
            result = self.scanner._write_register_safe(
                self.conn,
                address,
                value,
                register_type="coil",
                restore_on_exit=getattr(self.args, "restore_on_exit", False),
            )
            self.results["data"]["write_coil"] = result

            if result.get("success"):
                self.logger.success(f"[Write Coil] {value} written to coil {address}")
                if result.get("restored"):
                    self.logger.display(f"  Original value {result.get('original_value')} restored")
            else:
                self.logger.fail(f"[Write Coil] Failed: {result.get('error', 'Unknown error')}")

    def _handle_write_multiple(self):
        """Handle write multiple registers operation (FC 16)"""
        write_spec = getattr(self.args, "write_multiple", None)
        if not write_spec:
            return

        try:
            addr_str, values_str = write_spec.split("=")
            address = int(addr_str)
            values = [int(v.strip()) for v in values_str.split(",")]
        except ValueError as e:
            self.logger.fail(f"Invalid write-multiple spec: {write_spec} (use ADDR=V1,V2,V3): {e}")
            return

        if not getattr(self.args, "confirm", False):
            self.logger.fail("Write multiple registers requires --confirm flag")
            self.logger.display(f"    Would write {values} to registers starting at {address}")
            return

        if self.broadcast_mode:
            self._handle_broadcast_write(address, values, f"{len(values)} values")
        else:
            self.logger.display(
                f"Writing {len(values)} values to registers starting at {address}..."
            )
            result = self.scanner._write_multiple_registers(
                self.conn,
                address,
                values,
                restore_on_exit=getattr(self.args, "restore_on_exit", False),
            )
            self.results["data"]["write_multiple"] = result

            if result.get("success"):
                self.logger.success(
                    f"[Write Multiple] {len(values)} registers written at {address}"
                )
                if result.get("restored"):
                    self.logger.display("  Original values restored")
            else:
                self.logger.fail(f"[Write Multiple] Failed: {result.get('error', 'Unknown error')}")

    def _handle_write_multiple_coils(self):
        """Handle write multiple coils operation (FC 15)"""
        write_spec = getattr(self.args, "write_multiple_coils", None)
        if not write_spec:
            return

        try:
            addr_str, values_str = write_spec.split("=")
            address = int(addr_str)
            values = [bool(int(v.strip())) for v in values_str.split(",")]
        except ValueError as e:
            self.logger.fail(
                f"Invalid write-multiple-coils spec: {write_spec} (use ADDR=1,0,1,1): {e}"
            )
            return

        if not getattr(self.args, "confirm", False):
            self.logger.fail("Write multiple coils requires --confirm flag")
            self.logger.display(f"    Would write {values} to coils starting at {address}")
            return

        if self.broadcast_mode:
            self._handle_broadcast_write_multiple_coils(address, values)
        else:
            self.logger.display(f"Writing {len(values)} coils starting at {address}...")
            result = self.scanner._write_multiple_coils(
                self.conn,
                address,
                values,
                restore_on_exit=getattr(self.args, "restore_on_exit", False),
            )
            self.results["data"]["write_multiple_coils"] = result

            if result.get("success"):
                self.logger.success(
                    f"[Write Multiple Coils] {len(values)} coils written at {address}"
                )
                if result.get("restored"):
                    self.logger.display("  Original values restored")
            else:
                self.logger.fail(
                    f"[Write Multiple Coils] Failed: {result.get('error', 'Unknown error')}"
                )

    def _handle_test_write(self):
        """Handle test write access for registers"""
        thorough = getattr(self.args, "test_write_thorough", False)
        mode = "destructive" if thorough else "safe"

        # Destructive mode writes different values into live registers / flips
        # coils with only best-effort restore; gate it behind --confirm.
        # Safe (same-value) mode stays ungated by deliberate decision.
        if mode == "destructive" and not getattr(self.args, "confirm", False):
            self.logger.fail("--test-write-thorough (destructive) requires --confirm flag")
            return

        # Use "0-10" as default if scan_range is None or not set
        scan_range = getattr(self.args, "scan_range", None) or "0-10"
        register_type = getattr(self.args, "register_type", None) or "holding"

        # Map register type to internal format. Input registers and discrete
        # inputs are READ-ONLY in Modbus, so a write test against them is
        # invalid -- reject the request explicitly instead of silently coercing
        # to holding_registers and reporting write access for a different bank.
        type_map = {
            "holding": "holding_registers",
            "coil": "coils",
            "coils": "coils",
            "holding_registers": "holding_registers",
        }
        if register_type not in type_map:
            self.logger.fail(
                f"--test-write does not support register type '{register_type}' "
                "(input/discrete are read-only in Modbus; use 'holding' or 'coil')"
            )
            return
        reg_type = type_map[register_type]

        addresses = ProtocolParser.parse_address_range(scan_range)

        if mode == "safe":
            mode_desc = "safe (write same value)"
        else:
            mode_desc = "destructive (write & restore)"
        self.logger.display(f"[Test Write Access] Mode: {mode_desc}")
        self.logger.display(f"  Register type: {reg_type}")
        self.logger.display(f"  Address range: {scan_range} ({len(addresses)} addresses)")

        result = self.scanner._scan_write_access(
            self.conn,
            addresses,
            register_type=reg_type,
            mode=mode,
        )
        self.results["data"]["test_write"] = result

        writable = result.get("writable", [])
        read_only = result.get("read_only", [])
        errors = result.get("errors", [])

        w, r, e = len(writable), len(read_only), len(errors)
        self.logger.display(f"[Results] Writable: {w}, Read-only: {r}, Errors: {e}")

        if writable:
            self.logger.display("[Writable Registers]")
            for item in writable[:20]:  # Limit output
                self.logger.display(f"  {item['address']}: value={item['value']}")
            if len(writable) > 20:
                self.logger.display(f"  ... and {len(writable) - 20} more")

        if errors:
            self.logger.display("[Errors]")
            for item in errors[:10]:
                self.logger.display(f"  {item['address']}: {item['error']}")
            if len(errors) > 10:
                self.logger.display(f"  ... and {len(errors) - 10} more")

        # Security finding
        if writable:
            self.logger.security_finding(
                "Writable access",
                detail=f"Found {len(writable)} writable {reg_type}",
            )
