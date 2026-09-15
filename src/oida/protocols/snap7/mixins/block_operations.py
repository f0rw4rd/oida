"""
Snap7 Block Operations Mixin

Handles block operations, SZL, CPU control, and operational methods:
- CPU control (stop, cold start, hot start)
- Block operations (list, upload, download, delete, info)
- SZL enumeration and reading
- Date/time operations
- System maintenance (RAM->ROM, compress)
- Info actions (CLI wrappers)
- Security audit
- I/O monitor mode
- Findings reporting
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, Optional

from .device_info import decode_s7_field

if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


class BlockOperationsMixin(_ScannerBase):
    """Mixin providing block ops, SZL, CPU control, audit, monitor, and reporting."""

    # =========================================================================
    # CPU Control Methods
    # =========================================================================

    def cpu_stop(self, connection: Any) -> Dict[str, Any]:
        """Stop PLC CPU - DANGEROUS OPERATION"""
        try:
            connection.plc_stop()
            self.logger.success("CPU stopped successfully")
            return {"success": True, "action": "cpu_stop"}
        except Exception as e:
            self.logger.debug("cpu stop failed: %s", e)
            self.logger.fail(f"Failed to stop CPU: {e}")
            return {"success": False, "error": str(e)}

    def cpu_cold_start(self, connection: Any) -> Dict[str, Any]:
        """Cold start PLC CPU - DANGEROUS OPERATION"""
        try:
            connection.plc_cold_start()
            self.logger.success("CPU cold started successfully")
            return {"success": True, "action": "cpu_cold_start"}
        except Exception as e:
            self.logger.debug("cpu cold start failed: %s", e)
            self.logger.fail(f"Failed to cold start CPU: {e}")
            return {"success": False, "error": str(e)}

    def cpu_hot_start(self, connection: Any) -> Dict[str, Any]:
        """Hot start PLC CPU - DANGEROUS OPERATION"""
        try:
            connection.plc_hot_start()
            self.logger.success("CPU hot started successfully")
            return {"success": True, "action": "cpu_hot_start"}
        except Exception as e:
            self.logger.debug("cpu hot start failed: %s", e)
            self.logger.fail(f"Failed to hot start CPU: {e}")
            return {"success": False, "error": str(e)}

    # =========================================================================
    # Block Operation Methods
    # =========================================================================

    def list_blocks(self, connection: Any) -> Dict[str, Any]:
        """List all blocks on PLC"""
        from ..scanner import _suppress_snap7_logging

        with _suppress_snap7_logging():
            try:
                blocks = connection.list_blocks()
                result = {
                    "OB": blocks.OBCount,
                    "FB": blocks.FBCount,
                    "FC": blocks.FCCount,
                    "DB": blocks.DBCount,
                    "SFB": blocks.SFBCount,
                    "SFC": blocks.SFCCount,
                    "SDB": blocks.SDBCount,
                }
                self.logger.success("Block Summary:")
                self.logger.display(f"    OB (Organization Blocks): {result['OB']}")
                self.logger.display(f"    FB (Function Blocks):     {result['FB']}")
                self.logger.display(f"    FC (Functions):           {result['FC']}")
                self.logger.display(f"    DB (Data Blocks):         {result['DB']}")
                self.logger.display(f"    SFB (System FB):          {result['SFB']}")
                self.logger.display(f"    SFC (System FC):          {result['SFC']}")
                self.logger.display(f"    SDB (System DB):          {result['SDB']}")
                return {"success": True, "blocks": result}
            except Exception as e:
                self.logger.debug("list blocks failed: %s", e)
                self.logger.fail(f"Failed to list blocks: {e}")
                return {"success": False, "error": str(e)}

    def upload_db(
        self, connection: Any, db_num: int, output_file: Optional[str] = None
    ) -> Dict[str, Any]:
        """Upload (read) data block from PLC"""
        from ..scanner import _get_block_types
        from ....utils.common_types import safe_file_path

        Block = _get_block_types()
        try:
            # Get block info first to determine size
            try:
                block_info = connection.get_block_info(Block.DB, db_num)
                # MC7Size is the actual data size, LoadSize includes headers
                size = getattr(block_info, "MC7Size", None) or getattr(block_info, "LoadSize", 256)
            except Exception:
                # Fallback to default size if block info not available
                size = 256
                self.logger.debug(f"Could not get block info, using default size {size}")

            # Read full DB
            data = connection.db_read(db_num, 0, size)

            if output_file:
                output_path = safe_file_path(str(Path(output_file).resolve()))
                Path(output_path).write_bytes(data)
                self.logger.success(f"DB{db_num} ({size} bytes) saved to {output_path}")
            else:
                self.logger.success(f"DB{db_num}: {size} bytes")
                # Show hex preview (first 64 bytes)
                hex_preview = data[:64].hex()
                self.logger.display(f"    Data: {hex_preview}{'...' if len(data) > 64 else ''}")

            return {
                "success": True,
                "db_num": db_num,
                "size": size,
                "data": data.hex(),
            }
        except Exception as e:
            self.logger.debug("upload db failed: %s", e)
            self.logger.fail(f"Failed to upload DB{db_num}: {e}")
            return {"success": False, "error": str(e)}

    def download_db(self, connection: Any, db_num: int, data: bytes) -> Dict[str, Any]:
        """Download (write) data block to PLC - DANGEROUS OPERATION"""
        try:
            connection.db_write(db_num, 0, data)
            self.logger.success(f"DB{db_num} written ({len(data)} bytes)")
            return {"success": True, "db_num": db_num, "size": len(data)}
        except Exception as e:
            self.logger.debug("download db failed: %s", e)
            self.logger.fail(f"Failed to download DB{db_num}: {e}")
            return {"success": False, "error": str(e)}

    # =========================================================================
    # Enhanced Block Operations
    # =========================================================================

    @staticmethod
    def _get_block_type_map() -> Dict[str, Any]:
        """Get mapping of block type strings to snap7 Block constants."""
        from ..scanner import _get_block_types

        Block = _get_block_types()
        return {
            "OB": Block.OB,
            "FB": Block.FB,
            "FC": Block.FC,
            "DB": Block.DB,
            "SFB": Block.SFB,
            "SFC": Block.SFC,
            "SDB": Block.SDB,
        }

    def list_blocks_of_type(self, conn: Any, block_type: str) -> Dict[str, Any]:
        """List all blocks of a specific type"""
        try:
            type_map = self._get_block_type_map()
            blocks = conn.list_blocks_of_type(type_map[block_type], 1000)
            # Filter out invalid entries (empty slots return 0 or duplicates)
            seen = set()
            block_list = []
            for b in blocks:
                if b > 0 and b not in seen:
                    seen.add(b)
                    block_list.append(b)
            block_list.sort()
            if block_list:
                self.logger.success(f"{block_type} Blocks ({len(block_list)}):")
                for b in block_list:
                    self.logger.display(f"    {block_type}{b}")
            else:
                self.logger.display(f"{block_type} Blocks: None found")
            return {"success": True, "type": block_type, "blocks": block_list}
        except Exception as e:
            self.logger.debug("list blocks of type failed: %s", e)
            self.logger.fail(f"Failed to list {block_type} blocks: {e}")
            return {"success": False, "error": str(e)}

    def delete_block(self, conn: Any, block_type: str, block_num: int) -> Dict[str, Any]:
        """Delete a block from PLC"""
        try:
            type_map = self._get_block_type_map()
            conn.delete(type_map[block_type], block_num)
            self.logger.success(f"Deleted {block_type}{block_num}")
            return {"success": True, "deleted": f"{block_type}{block_num}"}
        except Exception as e:
            self.logger.debug("delete block failed: %s", e)
            self.logger.fail(f"Failed to delete {block_type}{block_num}: {e}")
            return {"success": False, "error": str(e)}

    def get_block_info(self, conn: Any, block_type: str, block_num: int) -> Dict[str, Any]:
        """Get detailed information about a specific block"""
        try:
            type_map = self._get_block_type_map()
            info = conn.get_block_info(type_map[block_type], block_num)
            result = {
                "block_type": info.BlkType,
                "block_number": info.BlkNumber,
                "block_lang": info.BlkLang,
                "block_flags": info.BlkFlags,
                "mc7_size": info.MC7Size,
                "load_size": info.LoadSize,
                "local_data": info.LocalData,
                "sbb_length": info.SBBLength,
                "checksum": info.CheckSum,
                "version": info.Version,
                "code_date": decode_s7_field(info.CodeDate),
                "interface_date": decode_s7_field(info.IntfDate),
                "author": decode_s7_field(getattr(info, "Author", "N/A")),
                "family": decode_s7_field(getattr(info, "Family", "N/A")),
                "header": decode_s7_field(getattr(info, "Header", "N/A")),
            }
            self.logger.success(f"{block_type}{block_num} Info:")
            self.logger.display(f"    MC7 Size: {result['mc7_size']} bytes")
            self.logger.display(f"    Load Size: {result['load_size']} bytes")
            self.logger.display(f"    Local Data: {result['local_data']} bytes")
            self.logger.display(f"    Version: {result['version']}")
            self.logger.display(f"    Checksum: 0x{result['checksum']:04X}")
            self.logger.display(f"    Code Date: {result['code_date']}")
            return {"success": True, **result}
        except Exception as e:
            self.logger.debug("get block info failed: %s", e)
            self.logger.fail(f"Failed to get {block_type}{block_num} info: {e}")
            return {"success": False, "error": str(e)}

    def upload_full_block(
        self, conn: Any, block_type: str, block_num: int, output_file: Optional[str] = None
    ) -> Dict[str, Any]:
        """Upload block with headers and footers"""
        from ....utils.common_types import safe_file_path
        from ....utils.protocol_helpers import DataFormatter

        try:
            type_map = self._get_block_type_map()
            # python-snap7 full_upload() returns a (bytearray, int) tuple
            data, size = conn.full_upload(type_map[block_type], block_num)
            if output_file:
                output_path = safe_file_path(str(Path(output_file).resolve()))
                Path(output_path).write_bytes(bytes(data))
                self.logger.success(
                    f"{block_type}{block_num} ({size} bytes) saved to {output_path}"
                )
            else:
                self.logger.success(f"{block_type}{block_num} ({size} bytes):")
                self.logger.display(DataFormatter.format_hex_dump(bytes(data[:128])))
                if size > 128:
                    self.logger.display(f"    ... ({size - 128} more bytes)")
            return {"success": True, "type": block_type, "num": block_num, "size": size}
        except Exception as e:
            self.logger.debug("upload full block failed: %s", e)
            self.logger.fail(f"Failed to upload {block_type}{block_num}: {e}")
            return {"success": False, "error": str(e)}

    # =========================================================================
    # Date/Time Operations
    # =========================================================================

    def get_plc_datetime(self, conn: Any) -> Dict[str, Any]:
        """Get PLC date and time"""
        try:
            dt = conn.get_plc_datetime()
            self.logger.success(f"PLC DateTime: {dt.isoformat()}")
            return {"success": True, "datetime": dt.isoformat()}
        except Exception as e:
            self.logger.debug("get plc datetime failed: %s", e)
            self.logger.fail(f"Failed to get PLC datetime: {e}")
            return {"success": False, "error": str(e)}

    def set_plc_datetime(self, conn: Any, dt) -> Dict[str, Any]:
        """Set PLC date and time"""
        try:
            conn.set_plc_datetime(dt)
            self.logger.success(f"PLC DateTime set to: {dt.isoformat()}")
            return {"success": True, "datetime": dt.isoformat()}
        except Exception as e:
            self.logger.debug("set plc datetime failed: %s", e)
            self.logger.fail(f"Failed to set PLC datetime: {e}")
            return {"success": False, "error": str(e)}

    def sync_plc_datetime(self, conn: Any) -> Dict[str, Any]:
        """Sync PLC time with host"""
        try:
            conn.set_plc_system_datetime()
            self.logger.success("PLC time synchronized with host")
            return {"success": True, "synced": True}
        except Exception as e:
            self.logger.debug("sync plc datetime failed: %s", e)
            self.logger.fail(f"Failed to sync PLC datetime: {e}")
            return {"success": False, "error": str(e)}

    # =========================================================================
    # System Maintenance
    # =========================================================================

    def copy_ram_to_rom(self, conn: Any, timeout: int = 1) -> Dict[str, Any]:
        """Copy RAM to ROM"""
        try:
            conn.copy_ram_to_rom(timeout)
            self.logger.success("RAM copied to ROM")
            return {"success": True, "action": "copy_ram_to_rom"}
        except Exception as e:
            self.logger.debug("copy ram to rom failed: %s", e)
            self.logger.fail(f"Failed to copy RAM to ROM: {e}")
            return {"success": False, "error": str(e)}

    def compress_memory(self, conn: Any, timeout: int = 1) -> Dict[str, Any]:
        """Compress PLC memory"""
        try:
            conn.compress(timeout)
            self.logger.success("Memory compressed")
            return {"success": True, "action": "compress"}
        except Exception as e:
            self.logger.debug("compress memory failed: %s", e)
            self.logger.fail(f"Failed to compress memory: {e}")
            return {"success": False, "error": str(e)}

    # =========================================================================
    # Enhanced Info Methods
    # =========================================================================

    def list_szl_ids(self, conn: Any) -> Dict[str, Any]:
        """List available SZL IDs"""
        try:
            szl_list = conn.read_szl_list()
            data = bytes(szl_list)

            # Parse SZL entries: each entry is 2 bytes (little-endian SZL ID)
            szl_entries = []
            for i in range(0, len(data), 2):
                if i + 2 <= len(data):
                    szl_id = int.from_bytes(data[i : i + 2], "little")
                    if szl_id != 0:  # Skip null entries
                        szl_entries.append(szl_id)

            # Remove duplicates and sort
            szl_entries = sorted(set(szl_entries))

            if szl_entries:
                self.logger.success("Available SZL IDs:")
                for szl_id in szl_entries:
                    self.logger.display(f"    0x{szl_id:04X}")
            else:
                self.logger.display("SZL IDs: None available")
            return {"success": True, "szl_ids": [hex(id) for id in szl_entries]}
        except Exception as e:
            self.logger.debug("list szl ids failed: %s", e)
            self.logger.fail(f"Failed to list SZL IDs: {e}")
            return {"success": False, "error": str(e)}

    def read_szl(self, conn: Any, szl_id: int, index: int = 0) -> Dict[str, Any]:
        """Read specific SZL"""
        from ....utils.protocol_helpers import DataFormatter

        try:
            data = conn.read_szl(szl_id, index)
            self.logger.success(f"SZL {hex(szl_id)}:{index}:")
            self.logger.display(DataFormatter.format_hex_dump(bytes(data)))
            return {"success": True, "szl_id": hex(szl_id), "index": index}
        except Exception as e:
            self.logger.debug("read szl failed: %s", e)
            self.logger.fail(f"Failed to read SZL {hex(szl_id)}: {e}")
            return {"success": False, "error": str(e)}

    def enumerate_szl(self, conn: Any) -> Dict[str, Any]:
        """Enumerate all valuable SZL data with parsed output"""
        from ..scanner import _suppress_snap7_logging
        from ..szl_parser import SZLParser

        results = {
            "success": True,
            "module_info": None,
            "protection": None,
            "diagnostics": None,
            "communication": None,
        }

        with _suppress_snap7_logging():
            # Critical SZLs for pentesting reconnaissance
            szl_targets = [
                (0x001C, 1, "module_info", "Module Identification"),
                (0x0132, 4, "protection", "Protection Level"),
                (0x0031, 0, "communication", "Communication Parameters"),
                (0x00A0, 0, "diagnostics", "Diagnostic Buffer"),
            ]

            self.logger.display("")
            self.logger.display("┌─────────────────────────────────────────────────────┐")
            self.logger.display("│ SZL Enumeration Results                             │")
            self.logger.display("├─────────────────────────────────────────────────────┤")

            for szl_id, index, key, description in szl_targets:
                try:
                    data = conn.read_szl(szl_id, index)
                    parsed = SZLParser.parse(szl_id, index, bytes(data))
                    results[key] = parsed

                    self.logger.display(f"│ {description:<51} │")
                    self.logger.display("│" + "─" * 53 + "│")

                    # Display parsed fields
                    for field, value in parsed.items():
                        if field not in ["szl_id", "index", "parsed", "raw"]:
                            field_str = f"  {field}: {value}"
                            self.logger.display(f"│ {field_str:<51} │")

                except Exception as e:
                    self.logger.debug("enumerate_szl: SZL 0x%04X failed: %s", szl_id, e)
                    results[key] = {"error": str(e)}
                    self.logger.display(f"│ {description}: Not available                        │")

                self.logger.display("│" + " " * 53 + "│")

            self.logger.display("└─────────────────────────────────────────────────────┘")
            self.logger.display("")

        return results

    # =========================================================================
    # Info Action Methods (CLI wrappers for internal methods)
    # =========================================================================

    def info_action(self, conn: Any) -> Dict[str, Any]:
        """Get combined device info (CPU info, state, order code, datetime, PDU)"""
        from ..scanner import _suppress_snap7_logging
        from ..device_lookup import lookup_device_name

        result = {"success": True}

        with _suppress_snap7_logging():
            # Get CPU info (with timeout)
            cpu_info = self._get_cpu_info(conn)

            # Get CPU state (with timeout)
            cpu_state = self._get_plc_status(conn)

            # Get order code
            order_code_info = {}
            try:
                oc = conn.get_order_code()
                code = getattr(oc, "OrderCode", None)
                if code:
                    if isinstance(code, bytes):
                        code = code.decode("ascii", errors="ignore").strip("\x00 ")
                    order_code_info = {
                        "order_code": code,
                        "version": (
                            f"V{oc.V1}.{oc.V2}.{oc.V3}" if oc.V1 or oc.V2 or oc.V3 else None
                        ),
                    }
            except Exception as e:
                self.logger.debug("info_action: order_code failed: %s", e)

            # Get PDU length
            pdu_length = None
            try:
                pdu_length = conn.get_pdu_length()
            except Exception as e:
                self.logger.debug("info_action: pdu_length failed: %s", e)

            # Get PLC datetime
            plc_datetime = None
            try:
                dt = conn.get_plc_datetime()
                if dt:
                    plc_datetime = dt.strftime("%Y-%m-%d %H:%M:%S")
            except Exception as e:
                self.logger.debug("info_action: plc_datetime failed: %s", e)

            # Get CP info
            cp_info = {}
            try:
                cp = conn.get_cp_info()
                if cp:
                    cp_info = {
                        "max_pdu": getattr(cp, "MaxPduLength", None),
                        "max_connections": getattr(cp, "MaxConnections", None),
                        "max_mpi_rate": getattr(cp, "MaxMpiRate", None),
                        "max_bus_rate": getattr(cp, "MaxBusRate", None),
                    }
            except Exception as e:
                self.logger.debug("info_action: cp_info failed: %s", e)

            # Build display (NXC style)
            order_code = order_code_info.get("order_code", "")
            device_name = lookup_device_name(order_code) if order_code else None

            # Module info
            if cpu_info and not cpu_info.get("error"):
                series = cpu_info.get("s7_series", "Unknown")
                module_type = cpu_info.get("module_type", "N/A")
                # Use device name from lookup if available
                display_name = device_name or module_type
                if order_code:
                    self.logger.success(f"{series} - {display_name} ({order_code})")
                else:
                    self.logger.success(f"{series} - {display_name}")
                if cpu_info.get("serial_number"):
                    self.logger.display(f"    Serial: {cpu_info['serial_number']}")
                result.update(cpu_info)
            else:
                # CPU info not available - use device lookup
                if order_code:
                    series = self._identify_series_from_order_code(order_code)
                    if device_name:
                        self.logger.success(f"{series} - {device_name} ({order_code})")
                    else:
                        self.logger.success(f"{series} ({order_code})")
                else:
                    self.logger.fail("CPU info not available")

            # Firmware
            if order_code_info.get("version"):
                self.logger.display(f"    Firmware: {order_code_info['version']}")
                result.update(order_code_info)

            # CPU state
            if cpu_state and not cpu_state.get("error"):
                status = cpu_state.get("status", "Unknown")
                self.logger.display(f"    Status: {status}")
                result.update(cpu_state)

            # PDU length
            if pdu_length:
                self.logger.display(f"    PDU: {pdu_length}")
                result["pdu_length"] = pdu_length

            # PLC datetime
            if plc_datetime:
                self.logger.display(f"    Time: {plc_datetime}")
                result["plc_datetime"] = plc_datetime

            # CP info (only if different from PDU)
            if cp_info.get("max_connections"):
                self.logger.display(f"    Max Connections: {cp_info['max_connections']}")
                result["cp_info"] = cp_info

        return result

    def enumerate_dbs_action(self, conn: Any) -> Dict[str, Any]:
        """Enumerate data blocks (CLI action wrapper)"""
        dbs = self._enumerate_data_blocks(conn)
        if dbs:
            self.logger.success(f"Found {len(dbs)} Data Blocks:")
            # _enumerate_data_blocks() returns a list of per-block dicts
            # ({"number": N, "size": ..., ...}), not bare ints -- iterating
            # it directly rendered "DB{'number': 1, 'size': ...}" here.
            for db in dbs:
                self.logger.display(f"    DB{db['number']}")
            return {"success": True, "data_blocks": dbs}
        self.logger.display("No accessible data blocks found")
        return {"success": True, "data_blocks": []}

    def test_memory_areas_action(self, conn: Any) -> Dict[str, Any]:
        """Test memory area access (CLI action wrapper)"""
        areas = self._test_memory_areas(conn)
        self.logger.success("Memory Area Access:")
        for area, info in areas.items():
            readable = "R" if info.get("readable") else "-"
            writable = "W" if info.get("writable") else "-"
            self.logger.display(f"    {area}: [{readable}{writable}]")
        return {"success": True, "memory_areas": areas}

    def scan_programs_action(self, conn: Any) -> Dict[str, Any]:
        """Scan for programs and blocks"""
        try:
            # Get block list summary
            block_list = conn.list_blocks()
            results = {
                "ob_count": block_list.OBCount,
                "fb_count": block_list.FBCount,
                "fc_count": block_list.FCCount,
                "sfb_count": block_list.SFBCount,
                "sfc_count": block_list.SFCCount,
                "db_count": block_list.DBCount,
                "sdb_count": block_list.SDBCount,
            }
            self.logger.success("Program Block Summary:")
            self.logger.display(f"    OB (Organization Blocks): {results['ob_count']}")
            self.logger.display(f"    FB (Function Blocks):     {results['fb_count']}")
            self.logger.display(f"    FC (Functions):           {results['fc_count']}")
            self.logger.display(f"    DB (Data Blocks):         {results['db_count']}")
            self.logger.display(f"    SFB (System FB):          {results['sfb_count']}")
            self.logger.display(f"    SFC (System FC):          {results['sfc_count']}")
            self.logger.display(f"    SDB (System DB):          {results['sdb_count']}")
            return {"success": True, **results}
        except Exception as e:
            self.logger.debug("scan programs action failed: %s", e)
            self.logger.fail(f"Failed to scan programs: {e}")
            return {"success": False, "error": str(e)}

    # =========================================================================
    # Security Audit
    # =========================================================================

    def audit(self, conn: Any, quick: bool = False) -> Dict[str, Any]:
        """Run security audit combining discovery, memory tests, and credential checks.

        Args:
            conn: S7 connection
            quick: If True, skip slow password brute-force test
        """
        from ..scanner import _suppress_snap7_logging

        self.logger.display("Starting S7 security audit%s...", " (quick)" if quick else "")
        results: Dict[str, Any] = {"success": True, "checks": {}}

        with _suppress_snap7_logging():
            # 1. Device identification
            self.logger.display("[1/7] Device identification")
            results["checks"]["cpu_info"] = self._get_cpu_info(conn)
            results["checks"]["firmware"] = self.get_firmware_version(conn)

            # 2. CPU protection level
            self.logger.display("[2/7] CPU protection level")
            results["checks"]["protection"] = self._check_protection_level(conn)

            # 3. Memory area access
            self.logger.display("[3/7] Memory area access")
            results["checks"]["memory_access"] = self._test_memory_areas(conn)

            # 4. Write access test
            self.logger.display("[4/7] Write access test")
            results["checks"]["write_access"] = self._test_write_access(conn)

            # 5. Block enumeration
            self.logger.display("[5/7] Block enumeration")
            results["checks"]["blocks"] = self._enumerate_data_blocks(conn)

            # 6. SZL disclosure
            self.logger.display("[6/7] SZL information disclosure")
            results["checks"]["szl"] = self.enumerate_szl(conn)

            # 7. Default passwords
            if quick:
                self.logger.display("[7/7] Default passwords (skipped - quick mode)")
                results["checks"]["passwords"] = {"skipped": True}
            else:
                self.logger.display("[7/7] Default password test")
                results["checks"]["passwords"] = self.bruteforce_password(
                    conn, rate_limit=0.5, continue_on_success=False
                )

        self.logger.display("Audit complete")
        return results

    # =========================================================================
    # Monitor Mode - Watch for I/O Changes
    # =========================================================================

    def monitor(
        self,
        conn: Any,
        areas: str = "I,Q,M",
        interval: float = 0.5,
        size: int = 16,
        duration: int = 0,
        show_bits: bool = False,
    ) -> Dict[str, Any]:
        """
        Monitor memory areas for changes.

        Args:
            conn: S7 connection
            areas: Comma-separated areas (I=inputs, Q=outputs, M=markers, DB1=block)
            interval: Polling interval in seconds
            size: Number of bytes to monitor per area
            duration: Monitor duration in seconds (0=infinite)
            show_bits: Show individual bit changes

        Returns:
            Dict with monitoring results and change log
        """
        import time
        from datetime import datetime

        # Parse areas to monitor
        area_list = [a.strip().upper() for a in areas.split(",")]
        area_config = []

        for area in area_list:
            if area == "I":
                area_config.append({"name": "I", "type": "input", "start": 0, "size": size})
            elif area == "Q":
                area_config.append({"name": "Q", "type": "output", "start": 0, "size": size})
            elif area == "M":
                area_config.append({"name": "M", "type": "marker", "start": 0, "size": size})
            elif area.startswith("DB"):
                try:
                    db_num = int(area[2:])
                    area_config.append(
                        {"name": area, "type": "db", "db": db_num, "start": 0, "size": size}
                    )
                except ValueError:
                    self.logger.warning(f"Invalid DB specification: {area}")

        if not area_config:
            self.logger.fail("No valid areas to monitor")
            return {"success": False, "error": "No valid areas"}

        # Initialize state
        state = {}
        changes = []
        start_time = time.time()

        # Read initial values
        for area in area_config:
            try:
                if area["type"] == "input":
                    data = bytes(conn.eb_read(area["start"], area["size"]))
                elif area["type"] == "output":
                    data = bytes(conn.ab_read(area["start"], area["size"]))
                elif area["type"] == "marker":
                    data = bytes(conn.mb_read(area["start"], area["size"]))
                elif area["type"] == "db":
                    data = bytes(conn.db_read(area["db"], area["start"], area["size"]))
                else:
                    continue
                state[area["name"]] = data
            except Exception as e:
                self.logger.warning(f"Cannot read {area['name']}: {e}")
                state[area["name"]] = None

        # Display header
        self.logger.display(f"Monitoring: {', '.join(a['name'] for a in area_config)}")
        self.logger.display(f"Interval: {interval}s, Size: {size} bytes per area")
        if duration > 0:
            self.logger.display(f"Duration: {duration}s")
        else:
            self.logger.display("Duration: infinite (Ctrl+C to stop)")
        self.logger.display("Watching for changes...")
        self.logger.display("")

        # Show initial state
        for area in area_config:
            if state.get(area["name"]):
                self.logger.display(f"[{area['name']}] Initial: {state[area['name']].hex()}")

        self.logger.display("")
        self.logger.display("-" * 60)

        try:
            iteration = 0
            while True:
                # Check duration
                if duration > 0 and (time.time() - start_time) >= duration:
                    break

                time.sleep(interval)
                iteration += 1
                now = datetime.now().strftime("%H:%M:%S.%f")[:-3]

                # Poll all areas
                for area in area_config:
                    try:
                        if area["type"] == "input":
                            new_data = bytes(conn.eb_read(area["start"], area["size"]))
                        elif area["type"] == "output":
                            new_data = bytes(conn.ab_read(area["start"], area["size"]))
                        elif area["type"] == "marker":
                            new_data = bytes(conn.mb_read(area["start"], area["size"]))
                        elif area["type"] == "db":
                            new_data = bytes(conn.db_read(area["db"], area["start"], area["size"]))
                        else:
                            continue

                        old_data = state.get(area["name"])
                        if old_data is None:
                            state[area["name"]] = new_data
                            continue

                        # Check for changes
                        if new_data != old_data:
                            # Find changed bytes
                            changed_bytes = []
                            for i in range(min(len(old_data), len(new_data))):
                                if old_data[i] != new_data[i]:
                                    changed_bytes.append(i)

                            # Log the change
                            change_entry = {
                                "time": now,
                                "area": area["name"],
                                "old": old_data.hex(),
                                "new": new_data.hex(),
                                "changed_bytes": changed_bytes,
                            }
                            changes.append(change_entry)

                            # Display change
                            self.logger.highlight(f"[{now}] {area['name']} CHANGED")

                            # Show byte-level changes
                            for idx in changed_bytes:
                                old_byte = old_data[idx]
                                new_byte = new_data[idx]
                                addr = f"{area['name']}{idx}"

                                if show_bits:
                                    # Show bit-level changes
                                    old_bits = format(old_byte, "08b")
                                    new_bits = format(new_byte, "08b")
                                    bit_changes = []
                                    for bit in range(8):
                                        if old_bits[7 - bit] != new_bits[7 - bit]:
                                            bit_val = "1" if new_bits[7 - bit] == "1" else "0"
                                            bit_changes.append(f"{addr}.{bit}={bit_val}")
                                    self.logger.display(
                                        f"  {addr}: 0x{old_byte:02X} ({old_bits}) -> "
                                        f"0x{new_byte:02X} ({new_bits})"
                                    )
                                    if bit_changes:
                                        self.logger.display(f"    Bits: {', '.join(bit_changes)}")
                                else:
                                    self.logger.display(
                                        f"  {addr}: 0x{old_byte:02X} -> 0x{new_byte:02X}"
                                    )

                            # Update state
                            state[area["name"]] = new_data

                    except Exception as e:
                        self.logger.debug(f"Error reading {area['name']}: {e}")

        except KeyboardInterrupt as e:
            self.logger.debug("monitor failed: %s", e)
            self.logger.display("")
            self.logger.display("Monitor stopped by user")

        # Summary
        elapsed = time.time() - start_time
        self.logger.display("")
        self.logger.display("-" * 60)
        self.logger.display(f"Monitoring complete: {elapsed:.1f}s, {len(changes)} changes detected")

        return {
            "success": True,
            "duration": elapsed,
            "iterations": iteration,
            "total_changes": len(changes),
            "changes": changes,
        }

    def _report_findings(self, results: Dict[str, Any]) -> None:
        """Report scanner findings with structured table output"""
        host, port = self.get_target_info()

        # Report host and service
        self.report_host_info(host)
        self.report_service_info(host, port=port, name="s7comm", proto="tcp")

        # Note: Device identity (PLC, Firmware, Status, Serial, Protection)
        # already displayed in _get_cpu_info() and _get_protection_level()

        # Report security concerns
        security_analysis = results.get("security_analysis", {})
        for concern in security_analysis.get("concerns", []):
            self.report_vulnerability(host, "s7_security", description=concern)
