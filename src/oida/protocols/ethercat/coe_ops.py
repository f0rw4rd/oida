"""CoE/SDO operations mixin for EtherCATScanner."""

from __future__ import annotations

import struct
from typing import Any, Dict, TYPE_CHECKING
from binascii import hexlify

from ...utils import ProgressTracker
from ...utils.export_utils import print_table
from .coe import (
    COMMON_SDO_OBJECTS,
    COE_SCAN_RANGES,
    get_coe_object_name as _coe_get_object_name,
    parse_coe_ranges,
)

if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


class CoeOpsMixin(_ScannerBase):
    """Mixin providing CoE (CANopen over EtherCAT) / SDO operations."""

    def _read_sdo_data(self, master: Any) -> Dict[int, Any]:
        """Read SDO (Service Data Object) information from slaves"""
        self.logger.display("Reading SDO data...")
        sdo_data = {}

        progress = ProgressTracker(len(master.slaves), logger=self.logger)

        targets = self._slave_filter()

        for i in range(len(master.slaves)):
            position = i + 1
            if position not in targets:
                progress.update()
                continue

            progress.update(msg=f"Reading SDO from slave {position}")

            try:
                sdo_data[i + 1] = self._read_slave_sdo(master, i)
            except Exception as e:
                self.logger.debug(f"Error reading SDO from slave {i + 1}: {e}")
                sdo_data[i + 1] = {"error": str(e)}

        return sdo_data

    def _read_slave_sdo(self, master: Any, slave_pos: int) -> Dict[str, Any]:
        """Read SDO data from a specific slave"""
        sdo_entries = {}
        slave = master.slaves[slave_pos]

        for index, subindex, description in COMMON_SDO_OBJECTS:
            try:
                data = slave.sdo_read(index, subindex)
                if data is not None:
                    sdo_entries[f"{index:04X}:{subindex:02X}"] = {
                        "index": index,
                        "subindex": subindex,
                        "description": description,
                        "data": hexlify(data).decode() if data else "",
                        "length": len(data) if data else 0,
                        "readable": True,
                    }
            except Exception as e:
                self.logger.debug(f"Error reading SDO {index:04X}:{subindex:02X}: {e}")

        return sdo_entries

    def _parse_sdo_address(self, addr_str: str) -> tuple:
        """Parse SDO address string like '0x1008:0' or '1:0x7000:1'

        Returns (slave_pos, index, subindex) - slave_pos is 0-based
        """
        parts = addr_str.split(":")
        if len(parts) == 2:
            # INDEX:SUBINDEX format (default to slave 1)
            slave_pos = 0
            index = int(parts[0], 0)  # Auto-detect hex/dec
            subindex = int(parts[1], 0)
        elif len(parts) == 3:
            # SLAVE:INDEX:SUBINDEX format
            slave_pos = int(parts[0]) - 1  # Convert to 0-based
            index = int(parts[1], 0)
            subindex = int(parts[2], 0)
        else:
            raise ValueError(f"Invalid SDO address format: {addr_str}")
        return slave_pos, index, subindex

    def _get_coe_object_name(self, index: int, subindex: int = 0) -> str:
        """Get standard name for CoE object index. Delegates to coe module."""
        return _coe_get_object_name(index, subindex)

    def _scan_coe_dictionary(self, master: Any) -> Dict[int, Any]:
        """Scan full CoE object dictionary with access type detection.

        Tests both read and write access for each object to determine:
        - RO: Read-only (read succeeds, write fails)
        - WO: Write-only (read fails, write succeeds)
        - RW: Read-write (both succeed)
        """
        # Determine scan ranges: custom --coe-range or defaults
        scan_ranges = COE_SCAN_RANGES
        if getattr(self, "coe_range", ""):
            try:
                parsed = parse_coe_ranges(self.coe_range)
                # Normalize 4-tuples to 3-tuples (drop subs — pysoem scans all subindices)
                scan_ranges = [(s, e, lbl) for s, e, lbl, _subs in parsed]
                total_indices = sum(end - start for start, end, _ in scan_ranges)
                self.logger.display(
                    f"Using custom CoE ranges: {len(scan_ranges)} range(s), {total_indices} indices"
                )
            except ValueError as e:
                self.logger.fail(f"Invalid --coe-range: {e}")
                return {}

        self.logger.display("Scanning CoE object dictionary (with access type detection)...")
        if not getattr(self, "confirm", False):
            self.logger.display(
                "  Read-only mode: write-access probing disabled (use --confirm to detect RW/WO)"
            )
        results = {}

        scan_slaves = self._slave_filter()

        for slave_idx in range(len(master.slaves)):
            position = slave_idx + 1
            if position not in scan_slaves:
                continue

            slave = master.slaves[slave_idx]
            slave_objects = {}
            access_stats = {"RO": 0, "WO": 0, "RW": 0}

            self.logger.display(f"Scanning slave {position}...")

            for start, end, category in scan_ranges:
                cat_objects = []
                for idx in range(start, end):
                    # Try to read subindex 0
                    read_ok = False
                    data = None
                    try:
                        data = slave.sdo_read(idx, 0)
                        read_ok = True
                    except Exception as e:
                        self.logger.debug(
                            f"EtherCAT CoE: sdo_read failed for index 0x{idx:04X}: {e}"
                        )

                    if read_ok and data is not None:
                        # Readable - test write access by writing same value back
                        write_ok = self._test_sdo_write_access(slave, idx, 0, data)
                        access = "RW" if write_ok else "RO"
                        access_stats[access] += 1

                        # Get name and type for export
                        name = self._get_coe_object_name(idx, 0)
                        type_str, _ = self._format_sdo_value(data.hex(), len(data))

                        obj_entry = {
                            "index": f"0x{idx:04X}",
                            "subindex": 0,
                            "data": data.hex(),
                            "size": len(data),
                            "category": category,
                            "access": access,
                            "name": name,
                            "type": type_str,
                        }
                        if len(data) <= 4:
                            obj_entry["value"] = int.from_bytes(data, "little")
                        cat_objects.append(obj_entry)

                        # Scan subindexes if subindex 0 indicates count
                        if len(data) == 1 and data[0] > 0 and data[0] <= 32:
                            consecutive_failures = 0
                            for sub in range(1, min(data[0] + 1, 33)):
                                try:
                                    sdata = slave.sdo_read(idx, sub)
                                    consecutive_failures = 0
                                    sub_write_ok = self._test_sdo_write_access(
                                        slave, idx, sub, sdata
                                    )
                                    sub_access = "RW" if sub_write_ok else "RO"
                                    access_stats[sub_access] += 1

                                    # Get name and type for export
                                    sub_name = self._get_coe_object_name(idx, sub)
                                    sub_type, _ = self._format_sdo_value(sdata.hex(), len(sdata))

                                    sub_entry = {
                                        "index": f"0x{idx:04X}",
                                        "subindex": sub,
                                        "data": sdata.hex(),
                                        "size": len(sdata),
                                        "category": category,
                                        "access": sub_access,
                                        "name": sub_name,
                                        "type": sub_type,
                                    }
                                    if len(sdata) <= 4:
                                        sub_entry["value"] = int.from_bytes(sdata, "little")
                                    cat_objects.append(sub_entry)
                                except Exception:
                                    # Read failed - test for write-only access
                                    if self._test_sdo_write_only(slave, idx, sub):
                                        consecutive_failures = 0
                                        access_stats["WO"] += 1
                                        wo_name = self._get_coe_object_name(idx, sub)
                                        cat_objects.append(
                                            {
                                                "index": f"0x{idx:04X}",
                                                "subindex": sub,
                                                "data": "",
                                                "size": 0,
                                                "category": category,
                                                "access": "WO",
                                                "name": wo_name,
                                                "type": "",
                                            }
                                        )
                                    else:
                                        consecutive_failures += 1
                                        # Stop after 3 consecutive failures (sparse object)
                                        if consecutive_failures >= 3:
                                            break
                    else:
                        # Read failed - try write-only test (write 0x00)
                        if self._test_sdo_write_only(slave, idx, 0):
                            access_stats["WO"] += 1
                            wo_name = self._get_coe_object_name(idx, 0)
                            cat_objects.append(
                                {
                                    "index": f"0x{idx:04X}",
                                    "subindex": 0,
                                    "data": "",
                                    "size": 0,
                                    "category": category,
                                    "access": "WO",
                                    "name": wo_name,
                                    "type": "",
                                }
                            )

                if cat_objects:
                    if category not in slave_objects:
                        slave_objects[category] = []
                    slave_objects[category].extend(cat_objects)

            results[position] = {
                "objects": slave_objects,
                "access_stats": access_stats,
            }
            total = sum(len(objs) for objs in slave_objects.values())
            self.logger.display(
                f"  Found {total} objects: {access_stats['RO']} RO, {access_stats['RW']} RW, {access_stats['WO']} WO"
            )

            # Display full table with access column and standard names (no truncation)
            if slave_objects:
                table_data = []
                for category, objects in slave_objects.items():
                    for obj in objects:
                        # Use stored name and type, compute formatted value for display
                        data_hex = obj.get("data", "")
                        _, val_str = self._format_sdo_value(data_hex, obj.get("size", 0))

                        table_data.append(
                            [
                                obj["index"],
                                str(obj["subindex"]),
                                obj.get("name", ""),
                                obj.get("access", "?"),
                                obj.get("type", ""),
                                val_str,
                                data_hex,  # Full data, no truncation
                            ]
                        )

                # Sort by index and subindex for better readability
                table_data.sort(key=lambda x: (x[0], int(x[1])))

                if table_data:
                    print_table(
                        table_data,  # All rows, no limit
                        ["Index", "Sub", "Name", "Access", "Type", "Value", "Data"],
                        title=f"Slave {position} CoE Dictionary ({total} objects: {access_stats['RO']} RO, {access_stats['RW']} RW, {access_stats['WO']} WO)",
                        logger=self.logger,
                    )

        return results

    def _format_sdo_value(self, data_hex: str, size: int) -> tuple:
        """Format SDO value with type information.

        Returns (type_str, value_str) tuple.
        """
        if not data_hex or size == 0:
            return ("", "")

        try:
            data = bytes.fromhex(data_hex)
        except ValueError:
            return ("", data_hex)

        # Determine type and format based on size
        if size == 1:
            val = data[0]
            return ("UINT8", str(val))
        elif size == 2:
            val = int.from_bytes(data, "little")
            return ("UINT16", f"0x{val:04X}" if val > 255 else str(val))
        elif size == 4:
            val = int.from_bytes(data, "little")
            return (
                "UINT32",
                f"0x{val:08X}" if val > 0xFFFF else f"0x{val:04X}" if val > 255 else str(val),
            )
        elif size == 8:
            val = int.from_bytes(data, "little")
            return ("UINT64", f"0x{val:016X}")
        else:
            # Try to decode as string (errors="ignore" never raises)
            text = data.decode("utf-8", errors="ignore").rstrip("\x00")
            if text and all(c.isprintable() or c.isspace() for c in text):
                return (f"STRING[{size}]", f'"{text}"')
            # Fall back to hex for unknown types
            return (f"BYTES[{size}]", data_hex[:32] + ("..." if len(data_hex) > 32 else ""))

    def _test_sdo_write_access(self, slave: Any, index: int, subindex: int, data: bytes) -> bool:
        """Test if SDO object is writable by writing the same value back.

        Even a same-value write back can latch a state change on objects with
        write side effects (control words, command/trigger objects, store/restore
        0x1010/0x1011). Gated behind --confirm; without it, classify as RO.
        Returns True if write succeeds, False otherwise.
        """
        if not getattr(self, "confirm", False):
            return False
        try:
            slave.sdo_write(index, subindex, data)
            return True
        except Exception as e:
            self.logger.debug(f"slave.sdo_write(index, subindex, data): {e}")
            return False

    def _test_sdo_write_only(self, slave: Any, index: int, subindex: int) -> bool:
        """Test if SDO object exists as write-only.

        Tries writing a small value (0x00) to detect write-only objects.
        Gated behind --confirm because writing 0x00 to control words
        (e.g. 0x6040) or store parameters (0x1010/0x1011) can cause
        state changes on live devices.

        Returns True if write succeeds, False otherwise.
        """
        if not getattr(self, "confirm", False):
            return False
        try:
            # Try 1-byte write first
            slave.sdo_write(index, subindex, bytes([0x00]))
            return True
        except Exception as e:
            self.logger.debug(f"slave.sdo_write(index, subindex, byte...: {e}")
            return False

    def _execute_sdo_read(self, master: Any) -> Dict[str, Any]:
        """Execute SDO read command"""
        result = {"success": False, "command": self.sdo_read_cmd}

        try:
            slave_pos, index, subindex = self._parse_sdo_address(self.sdo_read_cmd)

            if slave_pos < 0 or slave_pos >= len(master.slaves):
                result["error"] = f"Invalid slave position: {slave_pos + 1}"
                self.logger.fail(result["error"])
                return result

            slave = master.slaves[slave_pos]
            self.logger.display(
                f"Reading SDO 0x{index:04X}:{subindex} from slave {slave_pos + 1}..."
            )

            data = slave.sdo_read(index, subindex)
            result["slave"] = slave_pos + 1
            result["index"] = f"0x{index:04X}"
            result["subindex"] = subindex
            result["data"] = data.hex()
            result["size"] = len(data)
            result["success"] = True

            # Try to interpret
            if len(data) <= 4:
                result["value"] = int.from_bytes(data, "little")
                self.logger.success(
                    f"  0x{index:04X}:{subindex} = {data.hex()} (value: {result['value']})"
                )
            else:
                # Try as string (errors="ignore" never raises)
                text = data.decode("utf-8", errors="ignore").rstrip("\x00")
                if text.isprintable():
                    self.logger.success(f'  0x{index:04X}:{subindex} = "{text}"')
                else:
                    self.logger.success(f"  0x{index:04X}:{subindex} = {data.hex()}")

        except Exception as e:
            result["error"] = str(e)
            self.logger.fail(f"SDO read failed: {e}")

        return result

    def _execute_sdo_write(self, master: Any) -> Dict[str, Any]:
        """Execute SDO write command"""
        result = {"success": False, "command": self.sdo_write_cmd}

        try:
            # Parse format: [SLAVE:]INDEX:SUBINDEX:VALUE
            parts = self.sdo_write_cmd.split(":")
            if len(parts) == 3:
                # INDEX:SUBINDEX:VALUE
                slave_pos = 0
                index = int(parts[0], 0)
                subindex = int(parts[1], 0)
                value = int(parts[2], 0)
            elif len(parts) == 4:
                # SLAVE:INDEX:SUBINDEX:VALUE
                slave_pos = int(parts[0]) - 1
                index = int(parts[1], 0)
                subindex = int(parts[2], 0)
                value = int(parts[3], 0)
            else:
                result["error"] = (
                    "Invalid format. Use INDEX:SUBINDEX:VALUE or SLAVE:INDEX:SUBINDEX:VALUE"
                )
                self.logger.fail(result["error"])
                return result

            if slave_pos < 0 or slave_pos >= len(master.slaves):
                result["error"] = f"Invalid slave position: {slave_pos + 1}"
                self.logger.fail(result["error"])
                return result

            slave = master.slaves[slave_pos]
            self.logger.warning(
                f"Writing SDO 0x{index:04X}:{subindex} = 0x{value:X} to slave {slave_pos + 1}..."
            )

            # Determine data size (1, 2, or 4 bytes based on value)
            if value <= 0xFF:
                data = bytes([value])
            elif value <= 0xFFFF:
                data = struct.pack("<H", value)
            else:
                data = struct.pack("<I", value)

            slave.sdo_write(index, subindex, data)

            result["slave"] = slave_pos + 1
            result["index"] = f"0x{index:04X}"
            result["subindex"] = subindex
            result["value"] = value
            result["data"] = data.hex()
            result["success"] = True
            self.logger.success(f"  SDO write successful: 0x{index:04X}:{subindex} = 0x{value:X}")

        except Exception as e:
            result["error"] = str(e)
            self.logger.fail(f"SDO write failed: {e}")

        return result
