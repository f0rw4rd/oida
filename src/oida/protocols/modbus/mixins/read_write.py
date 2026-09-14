"""
Modbus Map Read/Write by Name Mixin

Handles reading and writing registers by friendly name using register maps:
- Read by name: --read-name "motor_speed" --register-map vfd/abb-acs880
- Write by name: --write-name "setpoint_1=75.5" --register-map generic --confirm
- List names: --list-names --register-map schneider-m340
- Search names: --search-name "speed" --register-map vfd/abb-acs880
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


class MapReadWriteMixin(_ScannerBase):
    """Mixin providing Modbus read/write by friendly register name."""

    def _get_resolver(self):
        """
        Get or create a MapNameResolver for the current register map.

        Returns:
            MapNameResolver instance, or None if no map is specified or map not found.
        """
        # Cache resolver on the instance
        if hasattr(self, "_map_resolver") and self._map_resolver is not None:
            return self._map_resolver

        map_name = getattr(self.args, "register_map", None)
        if not map_name:
            self.logger.fail("--register-map is required for name-based operations")
            return None

        from ..decoder import MapNameResolver

        try:
            self._map_resolver = MapNameResolver(map_name)
            return self._map_resolver
        except ValueError as e:
            self.logger.fail(str(e))
            return None

    def _handle_list_names(self):
        """
        List all named registers in the loaded register map.

        Shows a table of all registers with name, address, type, access, unit,
        and description. Triggered by --list-names --register-map <map>.
        """
        from ....utils.export_utils import print_table

        resolver = self._get_resolver()
        if not resolver:
            return

        entries = resolver.list_all()
        if not entries:
            self.logger.warning("No registers found in map")
            return

        self.logger.display(f"[Register Map] {resolver.vendor} {resolver.model}")
        self.logger.display(
            f"  Byte order: {resolver.byte_order}, Word order: {resolver.word_order}"
        )

        rows = []
        for entry in entries:
            addr_hex = f"0x{entry['address']:04X}"
            access = entry.get("access", "r")
            unit = entry.get("unit", "")
            name = entry["name"]
            dtype = entry.get("type", "u16")
            desc = entry.get("description", "")

            # Truncate long descriptions
            if len(desc) > 40:
                desc = desc[:37] + "..."

            # Show min/max if defined
            constraints = ""
            if entry.get("min") is not None or entry.get("max") is not None:
                min_v = entry.get("min", "")
                max_v = entry.get("max", "")
                constraints = f"[{min_v}..{max_v}]"

            value_info = f"{unit} {constraints}".strip() if (unit or constraints) else ""
            rows.append([name, addr_hex, dtype, access, value_info, desc])

        headers = ["Name", "Addr", "Type", "Acc", "Unit/Range", "Description"]
        print_table(
            rows,
            headers,
            title=f"Named Registers ({len(entries)} total)",
            logger=self.logger,
        )

    def _handle_search_name(self):
        """
        Search for registers by partial name or description match.

        Triggered by --search-name <query> --register-map <map>.
        """
        from ....utils.export_utils import print_table

        query = getattr(self.args, "search_name", None)
        if not query:
            return

        resolver = self._get_resolver()
        if not resolver:
            return

        matches = resolver.search(query)
        if not matches:
            self.logger.warning(f"No registers matching '{query}' found in map")
            return

        rows = []
        for entry in matches:
            addr_hex = f"0x{entry['address']:04X}"
            rows.append(
                [
                    entry["name"],
                    addr_hex,
                    entry.get("type", "u16"),
                    entry.get("access", "r"),
                    entry.get("unit", ""),
                    entry.get("description", ""),
                ]
            )

        headers = ["Name", "Addr", "Type", "Acc", "Unit", "Description"]
        print_table(
            rows,
            headers,
            title=f"Search Results for '{query}' ({len(matches)} matches)",
            logger=self.logger,
        )

    def _handle_read_name(self):
        """
        Read a register by friendly name from the register map.

        Loads the register map, resolves the name, reads the register(s),
        and displays the decoded engineering value.

        Triggered by: --read-name "motor_speed" --register-map <map>

        Examples:
            oida modbus 192.168.1.100 --register-map vfd/abb-acs880 --read-name speed_reference
            oida modbus 192.168.1.100 --register-map generic --read-name setpoint_1
        """
        name = getattr(self.args, "read_name", None)
        if not name:
            return

        resolver = self._get_resolver()
        if not resolver:
            return

        # Resolve the name
        entry = resolver.resolve(name)
        if not entry:
            # Show close matches as suggestions
            matches = resolver.search(name)
            self.logger.fail(f"Register name '{name}' not found in map")
            if matches:
                suggestions = [m["name"] for m in matches[:5]]
                self.logger.display(f"  Did you mean: {', '.join(suggestions)}")
            return

        # Determine register count
        regs_needed = resolver.get_registers_needed(entry)
        address = entry["address"]
        fc = entry["function_code"]
        # Use map's default unit ID only if the user did not explicitly pass --unit-id
        # (argparse default is None). An explicit --unit-id 1 must be honored verbatim.
        user_unit_id = getattr(self.args, "unit_id", None)
        default_uid = resolver.map_data.get("default_unit_id")
        if user_unit_id is None:
            unit_id = default_uid if default_uid is not None else 1
        else:
            unit_id = user_unit_id

        self.logger.display(
            f"[Read by Name] {entry['name']} @ address {address} "
            f"(FC {fc}, {entry['type']}, {regs_needed} reg{'s' if regs_needed > 1 else ''})"
        )

        try:
            # Read registers using the correct function code
            if fc == 1:
                result = self.conn.read_coils(address, count=1, device_id=unit_id)
            elif fc == 2:
                result = self.conn.read_discrete_inputs(address, count=1, device_id=unit_id)
            elif fc == 4:
                result = self.conn.read_input_registers(
                    address, count=regs_needed, device_id=unit_id
                )
            else:
                result = self.conn.read_holding_registers(
                    address, count=regs_needed, device_id=unit_id
                )

            if result.isError():
                exc_code = getattr(result, "exception_code", None)
                if exc_code is not None:
                    from ..constants import EXCEPTION_CODES

                    exc_name = EXCEPTION_CODES.get(exc_code, f"Unknown ({exc_code})")
                    self.logger.fail(f"  Read error: {exc_name} (exception code {exc_code})")
                else:
                    self.logger.fail(f"  Read error: {result}")
                return

            # Handle coils/discrete inputs
            if fc in (1, 2):
                value = result.bits[0]
                value_str = "ON (1)" if value else "OFF (0)"
                self.logger.success(f"  {entry['name']} = {value_str}")
                if entry.get("description"):
                    self.logger.display(f"  Description: {entry['description']}")
                self.results["data"]["read_name"] = {
                    "name": entry["name"],
                    "value": value,
                    "address": address,
                    "type": "coil" if fc == 1 else "discrete_input",
                }
                return

            # Decode register values
            raw_regs = list(result.registers)
            decoded = resolver.decode_value(entry, raw_regs)

            if decoded.get("error"):
                self.logger.fail(f"  Decode error: {decoded['error']}")
                self.logger.display(f"  Raw registers: {[hex(r) for r in raw_regs]}")
                return

            # Format the display value
            value = decoded["value"]
            if isinstance(value, float):
                if value.is_integer():
                    value_str = str(int(value))
                else:
                    value_str = f"{value:.6g}"
            else:
                value_str = str(value) if value is not None else "(null)"

            # Add enum label
            if decoded.get("enum_label"):
                value_str = f"{value_str} ({decoded['enum_label']})"

            # Add unit
            if decoded.get("unit"):
                value_str = f"{value_str} {decoded['unit']}"

            raw_hex = " ".join(f"0x{r:04X}" for r in raw_regs)

            self.logger.success(f"  {entry['name']} = {value_str}")
            self.logger.display(f"  Raw: {raw_hex}")
            if entry.get("description"):
                self.logger.display(f"  Description: {entry['description']}")
            if entry.get("access") in ("rw", "w"):
                self.logger.display(f"  Access: {entry['access']} (writable)")

            self.results["data"]["read_name"] = decoded

        except Exception as e:
            self.logger.fail(f"  Read failed: {e}")

    def _handle_write_name(self):
        """
        Write a register by friendly name using the register map.

        Resolves the name, validates the value (type, min/max), applies
        inverse scaling, encodes to raw registers, and writes.

        Triggered by: --write-name "setpoint_1=75.5" --register-map <map> --confirm

        Examples:
            oida modbus 192.168.1.100 --register-map generic --write-name "setpoint_1=75.5" --confirm
            oida modbus 192.168.1.100 --register-map vfd/abb-acs880 --write-name "speed_reference=5000" --confirm
        """
        write_spec = getattr(self.args, "write_name", None)
        if not write_spec:
            return

        # Parse name=value
        if "=" not in write_spec:
            self.logger.fail(f"Invalid write-name format: '{write_spec}' (use NAME=VALUE)")
            return

        name, value_str = write_spec.split("=", 1)
        name = name.strip()
        value_str = value_str.strip()

        resolver = self._get_resolver()
        if not resolver:
            return

        # Resolve the name
        entry = resolver.resolve(name)
        if not entry:
            matches = resolver.search(name)
            self.logger.fail(f"Register name '{name}' not found in map")
            if matches:
                suggestions = [m["name"] for m in matches[:5]]
                self.logger.display(f"  Did you mean: {', '.join(suggestions)}")
            return

        # Validate access mode
        access = entry.get("access", "r").lower()
        if access in ("r", "ro", "read", "read-only", "readonly"):
            self.logger.fail(f"Register '{entry['name']}' is read-only (access: {entry['access']})")
            return

        address = entry["address"]
        fc = entry["function_code"]
        dtype = entry["type"]
        # Use map's default unit ID only if the user did not explicitly pass --unit-id
        # (argparse default is None). An explicit --unit-id 1 must be honored verbatim.
        user_unit_id = getattr(self.args, "unit_id", None)
        default_uid = resolver.map_data.get("default_unit_id")
        if user_unit_id is None:
            unit_id = default_uid if default_uid is not None else 1
        else:
            unit_id = user_unit_id

        # Handle coil writes
        is_coil = fc in (1, 5) or entry["section"] == "coils"
        if is_coil:
            try:
                coil_val = value_str.lower()
                if coil_val in ("1", "true", "on", "yes"):
                    coil_value = True
                elif coil_val in ("0", "false", "off", "no"):
                    coil_value = False
                else:
                    raise ValueError(
                        f"Invalid coil value: {value_str} (use 0/1, on/off, true/false)"
                    )
            except ValueError as e:
                self.logger.fail(str(e))
                return

            if not getattr(self.args, "confirm", False):
                self.logger.fail("Write operation requires --confirm flag")
                self.logger.display(
                    f"  Would write {'ON' if coil_value else 'OFF'} to coil "
                    f"'{entry['name']}' at address {address}"
                )
                self.results["success"] = False
                self.results["data"]["refused"] = "--write-name requires --confirm"
                return

            self.logger.display(
                f"[Write by Name] {entry['name']} @ coil {address} = "
                f"{'ON' if coil_value else 'OFF'}"
            )
            try:
                result = self.conn.write_coil(address, coil_value, device_id=unit_id)
                if result.isError():
                    self.logger.fail(f"  Coil write failed: {result}")
                else:
                    self.logger.success(
                        f"  {entry['name']} = {'ON' if coil_value else 'OFF'} written successfully"
                    )
                self.results["data"]["write_name"] = {
                    "name": entry["name"],
                    "value": coil_value,
                    "address": address,
                    "type": "coil",
                    "success": not result.isError(),
                }
            except Exception as e:
                self.logger.fail(f"  Write failed: {e}")
            return

        # Encode the engineering value to raw register values
        try:
            registers = resolver.encode_value(entry, value_str)
        except ValueError as e:
            self.logger.fail(f"  Validation error: {e}")
            return
        except Exception as e:
            self.logger.fail(f"  Encoding error for '{value_str}' as {dtype}: {e}")
            return

        # Build display string
        unit = entry.get("unit", "")
        display_value = f"{value_str}"
        if unit:
            display_value = f"{value_str} {unit}"

        reg_count = len(registers)
        addr_range = f"{address}" if reg_count == 1 else f"{address}-{address + reg_count - 1}"

        # Check for confirmation
        if not getattr(self.args, "confirm", False):
            self.logger.fail("Write operation requires --confirm flag")
            self.logger.display(
                f"  Would write {display_value} to '{entry['name']}' "
                f"(address {addr_range}, type {dtype})"
            )
            self.logger.display(f"  Raw register values: {[hex(r) for r in registers]}")
            if entry.get("description"):
                self.logger.display(f"  Description: {entry['description']}")
            self.results["success"] = False
            self.results["data"]["refused"] = "--write-name requires --confirm"
            return

        self.logger.display(
            f"[Write by Name] {entry['name']} @ address {addr_range} = {display_value} ({dtype})"
        )

        try:
            if reg_count == 1:
                result = self.conn.write_register(address, registers[0], device_id=unit_id)
            else:
                result = self.conn.write_registers(address, registers, device_id=unit_id)

            if result.isError():
                exc_code = getattr(result, "exception_code", None)
                if exc_code is not None:
                    from ..constants import EXCEPTION_CODES

                    exc_name = EXCEPTION_CODES.get(exc_code, f"Unknown ({exc_code})")
                    self.logger.fail(f"  Write failed: {exc_name} (exception code {exc_code})")
                else:
                    self.logger.fail(f"  Write failed: {result}")
            else:
                self.logger.success(f"  {entry['name']} = {display_value} written successfully")
                self.logger.display(f"  Raw registers: {[hex(r) for r in registers]}")

            self.results["data"]["write_name"] = {
                "name": entry["name"],
                "value": value_str,
                "engineering_value": display_value,
                "address": address,
                "type": dtype,
                "registers": registers,
                "success": not result.isError(),
            }

        except Exception as e:
            self.logger.fail(f"  Write failed: {e}")
            self.results["data"]["write_name"] = {
                "name": entry["name"],
                "value": value_str,
                "address": address,
                "error": str(e),
            }
