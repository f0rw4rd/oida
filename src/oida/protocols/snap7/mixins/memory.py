"""
Snap7 Memory Mixin

Handles data block enumeration and memory read/write operations:
- Data block enumeration and access testing
- Memory area access permission testing
- Sample value reading from accessible areas
- Read operations: inputs, outputs, markers, timers, counters, DB areas
- Write operations: DB area, markers, outputs, inputs, timers, counters
- DB dump and fill operations
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List

from oida.utils.common_types import Category

if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


class MemoryMixin(_ScannerBase):
    """Mixin providing data block enumeration and memory read/write operations."""

    def _enumerate_data_blocks(self, connection: Any) -> List[Dict[str, Any]]:
        """Enumerate accessible data blocks"""
        from ..scanner import _get_block_types
        from ....utils import ProgressTracker

        self.logger.debug("Enumerating data blocks (max=%d)", self.max_dbs)
        data_blocks = []
        errors_count = 0
        Block = _get_block_types()

        self.logger.display(f"Enumerating data blocks (max: {self.max_dbs})")
        progress = ProgressTracker(self.max_dbs, logger=self.logger)

        for db_number in range(1, self.max_dbs + 1):
            try:
                # Try to get DB info
                db_info = connection.get_block_info(Block.DB, db_number)

                if db_info:
                    # python-snap7 TS7BlockInfo has no BlkLen; the block size is
                    # MC7Size (falling back to LoadSize). The old .BlkLen raised
                    # AttributeError that the except below miscounted as "DB not
                    # accessible", so DB enumeration never returned a block.
                    size = getattr(db_info, "MC7Size", None) or getattr(db_info, "LoadSize", 0)
                    db_data = {
                        "number": db_number,
                        "size": size,
                        "type": "DB",
                        "accessible": True,
                    }

                    # Try to read first few bytes
                    if self.read_values and not self.read_only:
                        try:
                            data = connection.db_read(db_number, 0, min(10, size))
                            db_data["readable"] = True
                            db_data["sample_data"] = data.hex()[:20] + "..."
                        except Exception as e:
                            self.logger.debug(f"DB{db_number} not readable: {e}")
                            db_data["readable"] = False

                    data_blocks.append(db_data)
                    self.logger.debug(f"Found DB{db_number}: {size} bytes")

            except Exception as e:
                # DB doesn't exist or not accessible - just count errors
                errors_count += 1
                if errors_count == 1:
                    # Only log the first error as a sample
                    self.logger.debug(f"Sample error for DB enumeration: {str(e)[:50]}...")

            progress.update()

        if errors_count > 0:
            self.logger.debug(f"Total DB enumeration errors: {errors_count}")

        self.logger.display(f"Found {len(data_blocks)} accessible data blocks")
        return data_blocks

    def _test_memory_areas(self, connection: Any) -> Dict[str, Any]:
        """Test access to different memory areas"""
        from ..constants import S7MemoryArea

        from ....utils import parse_bool

        self.logger.debug("Testing memory area access")
        memory_areas = {}

        # The scanner defaults read_only=True with no CLI toggle, so the active
        # write-back probe (a real write PDU, same value back) is gated on
        # --confirm rather than read_only.
        probe_writes = parse_bool(self.args.get("confirm", False))

        areas_to_test = [
            ("Inputs", S7MemoryArea.PE, "I"),
            ("Outputs", S7MemoryArea.PA, "Q"),
            ("Markers", S7MemoryArea.MK, "M"),
            ("Counters", S7MemoryArea.CT, "C"),
            ("Timers", S7MemoryArea.TM, "T"),
        ]

        self.logger.display("Testing memory area access permissions")

        for area_name, area_code, area_prefix in areas_to_test:
            area_info = {
                "name": area_name,
                "prefix": area_prefix,
                "readable": False,
                "writable": False,
                "size": 0,
            }

            try:
                # Try to read first byte
                data = connection.read_area(area_code, 0, 0, 1)
                area_info["readable"] = True
                self.logger.debug(f"{area_name} area is readable")

                # Test write access (see probe_writes note above).
                if probe_writes:
                    try:
                        # Write the same value back
                        connection.write_area(area_code, 0, 0, data)
                        area_info["writable"] = True
                        self.logger.display(f"WRITABLE: {area_name} area")

                        # Report security finding
                        host, port = self.get_target_info()
                        self.logger.security_finding(
                            "Writable access",
                            category=Category.ACCESS_CONTROL,
                            detail=f"{area_name} memory area is writable",
                        )
                    except Exception as e:
                        self.logger.debug(f"Write test failed for {area_name}: {e}")

            except Exception as e:
                self.logger.debug(f"Cannot access {area_name} area: {e}")

            memory_areas[area_prefix] = area_info

        return memory_areas

    def _read_sample_values(self, connection: Any, results: Dict[str, Any]) -> Dict[str, Any]:
        """Read sample values from accessible areas"""
        from ..constants import S7MemoryArea

        samples = {}

        # Read from accessible DBs
        for db in results.get("data_blocks", [])[:5]:  # Limit to first 5 DBs
            if db.get("readable"):
                try:
                    data = connection.db_read(db["number"], 0, min(20, db["size"]))
                    samples[f"DB{db['number']}"] = {
                        "data": data.hex(),
                        "size": len(data),
                    }
                except Exception as e:
                    self.logger.debug(f"Error reading DB{db['number']}: {e}")

        # Read from memory areas
        for area_prefix, area_info in results.get("memory_areas", {}).items():
            if area_info.get("readable"):
                try:
                    area_code = {
                        "I": S7MemoryArea.PE,
                        "Q": S7MemoryArea.PA,
                        "M": S7MemoryArea.MK,
                    }.get(area_prefix)

                    if area_code:
                        data = connection.read_area(area_code, 0, 0, 10)
                        samples[f"{area_prefix}0.0-{area_prefix}1.1"] = {
                            "data": data.hex(),
                            "size": len(data),
                        }
                except Exception as e:
                    self.logger.debug(f"Error reading {area_prefix} area: {e}")

        return samples

    # =========================================================================
    # Memory Read Methods
    # =========================================================================

    def read_inputs(self, connection: Any, start: int, size: int) -> Dict[str, Any]:
        """Read process inputs (I/PE area)"""
        from ....utils.protocol_helpers import DataFormatter

        try:
            data = connection.eb_read(start, size)
            self.logger.success(f"Inputs I{start}.0 - I{start + size - 1}.7:")
            self.logger.display(DataFormatter.format_hex_dump(data))
            return {"success": True, "area": "I", "start": start, "size": size, "data": data.hex()}
        except Exception as e:
            self.logger.debug("read inputs failed: %s", e)
            self.logger.fail(f"Failed to read inputs: {e}")
            return {"success": False, "error": str(e)}

    def read_outputs(self, connection: Any, start: int, size: int) -> Dict[str, Any]:
        """Read process outputs (Q/PA area)"""
        from ....utils.protocol_helpers import DataFormatter

        try:
            data = connection.ab_read(start, size)
            self.logger.success(f"Outputs Q{start}.0 - Q{start + size - 1}.7:")
            self.logger.display(DataFormatter.format_hex_dump(data))
            return {"success": True, "area": "Q", "start": start, "size": size, "data": data.hex()}
        except Exception as e:
            self.logger.debug("read outputs failed: %s", e)
            self.logger.fail(f"Failed to read outputs: {e}")
            return {"success": False, "error": str(e)}

    def read_markers(self, connection: Any, start: int, size: int) -> Dict[str, Any]:
        """Read markers/flags (M/MK area)"""
        from ....utils.protocol_helpers import DataFormatter

        try:
            data = connection.mb_read(start, size)
            self.logger.success(f"Markers M{start}.0 - M{start + size - 1}.7:")
            self.logger.display(DataFormatter.format_hex_dump(data))
            return {"success": True, "area": "M", "start": start, "size": size, "data": data.hex()}
        except Exception as e:
            self.logger.debug("read markers failed: %s", e)
            self.logger.fail(f"Failed to read markers: {e}")
            return {"success": False, "error": str(e)}

    def read_timers(self, connection: Any, start: int, count: int) -> Dict[str, Any]:
        """Read timers (S7-300/400 only)"""
        from ....utils.protocol_helpers import DataFormatter

        try:
            data = connection.tm_read(start, count)
            self.logger.success(f"Timers T{start} - T{start + count - 1}:")
            self.logger.display(DataFormatter.format_hex_dump(data))
            return {
                "success": True,
                "area": "T",
                "start": start,
                "count": count,
                "data": data.hex(),
            }
        except Exception as e:
            self.logger.debug("read timers failed: %s", e)
            self.logger.fail(f"Failed to read timers: {e}")
            return {"success": False, "error": str(e)}

    def read_counters(self, connection: Any, start: int, count: int) -> Dict[str, Any]:
        """Read counters (S7-300/400 only)"""
        from ....utils.protocol_helpers import DataFormatter

        try:
            data = connection.ct_read(start, count)
            self.logger.success(f"Counters C{start} - C{start + count - 1}:")
            self.logger.display(DataFormatter.format_hex_dump(data))
            return {
                "success": True,
                "area": "C",
                "start": start,
                "count": count,
                "data": data.hex(),
            }
        except Exception as e:
            self.logger.debug("read counters failed: %s", e)
            self.logger.fail(f"Failed to read counters: {e}")
            return {"success": False, "error": str(e)}

    def read_db_area(self, connection: Any, db: int, start: int, size: int) -> Dict[str, Any]:
        """Read specific area from data block"""
        from ....utils.protocol_helpers import DataFormatter

        try:
            data = connection.db_read(db, start, size)
            self.logger.success(f"DB{db} offset {start}-{start + size - 1}:")
            self.logger.display(DataFormatter.format_hex_dump(data))
            return {"success": True, "db": db, "start": start, "size": size, "data": data.hex()}
        except Exception as e:
            self.logger.debug("read db area failed: %s", e)
            self.logger.fail(f"Failed to read DB{db}: {e}")
            return {"success": False, "error": str(e)}

    def dump_db(self, connection: Any, db_num: int) -> Dict[str, Any]:
        """Dump entire data block with hex view"""
        from ..scanner import _get_block_types
        from ....utils.protocol_helpers import DataFormatter

        Block = _get_block_types()
        try:
            # Get block size first
            block_info = connection.get_block_info(Block.DB, db_num)
            size = getattr(block_info, "MC7Size", None) or getattr(block_info, "LoadSize", 256)
            data = connection.db_read(db_num, 0, size)
            self.logger.success(f"DB{db_num} Full Dump ({size} bytes):")
            self.logger.display(DataFormatter.format_hex_dump(data))
            return {"success": True, "db": db_num, "size": size, "data": data.hex()}
        except Exception as e:
            self.logger.debug("dump db failed: %s", e)
            self.logger.fail(f"Failed to dump DB{db_num}: {e}")
            return {"success": False, "error": str(e)}

    # =========================================================================
    # Memory Write Methods
    # =========================================================================

    def write_db_area(self, conn: Any, db: int, start: int, data: bytes) -> Dict[str, Any]:
        """Write to data block area"""
        try:
            conn.db_write(db, start, data)
            self.logger.success(f"Written {len(data)} bytes to DB{db} at offset {start}")
            return {"success": True, "db": db, "start": start, "size": len(data)}
        except Exception as e:
            self.logger.debug("write db area failed: %s", e)
            self.logger.fail(f"Failed to write DB{db}: {e}")
            return {"success": False, "error": str(e)}

    def write_markers(self, conn: Any, start: int, data: bytes) -> Dict[str, Any]:
        """Write to markers area"""
        try:
            conn.mb_write(start, len(data), data)
            self.logger.success(f"Written {len(data)} bytes to M{start}")
            return {"success": True, "area": "M", "start": start, "size": len(data)}
        except Exception as e:
            self.logger.debug("write markers failed: %s", e)
            self.logger.fail(f"Failed to write markers: {e}")
            return {"success": False, "error": str(e)}

    def write_outputs(self, conn: Any, start: int, data: bytes) -> Dict[str, Any]:
        """Write to outputs area"""
        try:
            conn.ab_write(start, data)
            self.logger.success(f"Written {len(data)} bytes to Q{start}")
            return {"success": True, "area": "Q", "start": start, "size": len(data)}
        except Exception as e:
            self.logger.debug("write outputs failed: %s", e)
            self.logger.fail(f"Failed to write outputs: {e}")
            return {"success": False, "error": str(e)}

    def write_inputs(self, conn: Any, start: int, data: bytes) -> Dict[str, Any]:
        """Write to inputs area (use with caution)"""
        try:
            conn.eb_write(start, len(data), bytearray(data))
            self.logger.success(f"Written {len(data)} bytes to I{start}")
            return {"success": True, "area": "I", "start": start, "size": len(data)}
        except Exception as e:
            self.logger.debug("write inputs failed: %s", e)
            self.logger.fail(f"Failed to write inputs: {e}")
            return {"success": False, "error": str(e)}

    def write_timers(self, conn: Any, start: int, data: bytes) -> Dict[str, Any]:
        """Write to timers (S7-300/400 only)"""
        try:
            # Timers are 2 bytes each
            amount = len(data) // 2
            conn.tm_write(start, amount, bytearray(data))
            self.logger.success(f"Written {amount} timer(s) starting at T{start}")
            return {"success": True, "area": "T", "start": start, "count": amount}
        except Exception as e:
            self.logger.debug("write timers failed: %s", e)
            self.logger.fail(f"Failed to write timers: {e}")
            return {"success": False, "error": str(e)}

    def write_counters(self, conn: Any, start: int, data: bytes) -> Dict[str, Any]:
        """Write to counters (S7-300/400 only)"""
        try:
            # Counters are 2 bytes each
            amount = len(data) // 2
            conn.ct_write(start, amount, bytearray(data))
            self.logger.success(f"Written {amount} counter(s) starting at C{start}")
            return {"success": True, "area": "C", "start": start, "count": amount}
        except Exception as e:
            self.logger.debug("write counters failed: %s", e)
            self.logger.fail(f"Failed to write counters: {e}")
            return {"success": False, "error": str(e)}

    def db_fill(self, conn: Any, db_num: int, fill_byte: int) -> Dict[str, Any]:
        """Fill entire data block with a byte value"""
        try:
            conn.db_fill(db_num, fill_byte)
            self.logger.success(f"Filled DB{db_num} with 0x{fill_byte:02X}")
            return {"success": True, "db": db_num, "fill_byte": f"0x{fill_byte:02X}"}
        except Exception as e:
            self.logger.debug("db fill failed: %s", e)
            self.logger.fail(f"Failed to fill DB{db_num}: {e}")
            return {"success": False, "error": str(e)}
