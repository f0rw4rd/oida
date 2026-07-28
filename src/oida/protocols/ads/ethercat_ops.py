#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ADS EtherCAT bridge operations mixin.

Provides EtherCAT-over-ADS methods for the ADSScanner class:
- File operations (list, read, delete via ADS and FoE)
- Task data reading
- Registry access
- Route management
- PLC program download
- EtherCAT slave scanning and enumeration
- CoE (CANopen over EtherCAT) SDO scanning
- EEPROM/SII dumping via ADS
- ESC register reading via ADS
- FoE (File over EtherCAT) read/write/scan
- SoE (Servo over EtherCAT) scanning
- FSoE (Safety over EtherCAT) scanning
- CoE fuzzing

These methods are mixed into ADSScanner via inheritance.
"""

import os
import re
import struct
from typing import Dict, Any, Optional

from ...utils import ProgressTracker

# Shared CoE definitions
from ..ethercat.coe import (
    get_al_state_name,
    COE_SCAN_RANGES,
    get_coe_object_name,
    parse_coe_ranges,
)
from ..ethercat.constants import lookup_vendor, get_al_status_error, ESC_REGISTER_MAP
from ..ethercat.soe import SOE_ELEMENTS, SOE_STANDARD_IDNS, encode_soe_offset
from ..ethercat.foe import FOE_COMMON_FILENAMES
from ..ethercat.fsoe import FSOE_COE_OBJECTS, FSOE_PARAM_OBJECTS
from ..ethercat.eeprom import parse_sii_header

# ADS protocol constants
from .constants import (
    ADS_ERROR_CODES,
    ADS_FILE_FLAG,
    ADS_FUZZ_DELAY,
    ADS_IDX_GRP,
)

# Shared helpers
from .helpers import (
    _get_pyads,
    _read_raw,
    _read_coe_string,
    _read_coe_sdo,
    _read_sdo_entry_desc,
    _write_raw,
    _write_coe_sdo,
    _read_write_raw,
    _is_ads_timeout,
    _extract_ads_error,
    _extract_ads_error_code,
    COE_SDO_OFFSET,
)

import logging

logger = logging.getLogger(__name__)

# Upper bound on the device-reported EtherCAT slave count. The protocol allows
# up to 65535 slaves per segment, but real networks are far smaller; this caps
# the per-slave scan loop so a spoofed/garbage count can't DoS the scanner.
MAX_SLAVE_PORTS = 1024


class EtherCATOpsMixin:
    """Mixin providing EtherCAT-over-ADS bridge operations for ADSScanner."""

    def _list_files(self, path: str = "C:\\TwinCAT\\") -> Dict[str, Any]:
        """List files via SystemService file access (port 10000).

        Uses index groups:
        - 0x78 (FILE_OPEN): Open file/directory
        - 0x79 (FILE_CLOSE): Close handle
        - 0x85 (FILE_BROWSE): Browse directory
        """
        result = {
            "success": False,
            "path": path,
            "files": [],
        }

        self.logger.display(f"Listing files: {path} (port 10000)...")
        pyads = _get_pyads()

        try:
            # Connect to SystemService port
            sys_conn = pyads.Connection(self.ams_netid, 10000)
            sys_conn.open()
            sys_conn.set_timeout(self.ads_timeout_ms)

            try:
                # Use FILE_BROWSE with pattern
                browse_pattern = path.encode("utf-8") + b"*\x00"

                # Request: handle=1, send pattern, expect file info
                handle = 1
                file_data = _read_write_raw(
                    sys_conn,
                    ADS_IDX_GRP["FILE_BROWSE"],
                    handle,
                    320,  # TcFileFindData struct size
                    browse_pattern,
                )

                if file_data and len(file_data) >= 320:
                    # Parse TcFileFindData
                    # 0-3: hFile, 4-7: dwFileAttributes, 8-47: reserved, 48-307: cFileName
                    file_handle = struct.unpack("<I", file_data[0:4])[0]
                    if file_handle == 0:
                        self.logger.debug("File browse returned handle=0 (no results)")
                        result["success"] = True
                        return result

                    attrs = struct.unpack("<I", file_data[4:8])[0]
                    filename = file_data[48:308].split(b"\x00")[0].decode("utf-8", errors="ignore")

                    is_dir = (attrs & 0x10) != 0

                    if filename:
                        result["files"].append(
                            {
                                "name": filename,
                                "is_directory": is_dir,
                                "attributes": attrs,
                            }
                        )
                        self.logger.display(f"  {'[DIR]' if is_dir else '[FILE]'} {filename}")

                        # Continue enumeration with same handle
                        while True:
                            try:
                                next_data = _read_write_raw(
                                    sys_conn, ADS_IDX_GRP["FILE_BROWSE"], file_handle, 320, b""
                                )
                                if not next_data or len(next_data) < 320:
                                    break

                                attrs = struct.unpack("<I", next_data[4:8])[0]
                                filename = (
                                    next_data[48:308]
                                    .split(b"\x00")[0]
                                    .decode("utf-8", errors="ignore")
                                )

                                if not filename:
                                    break

                                is_dir = (attrs & 0x10) != 0
                                result["files"].append(
                                    {
                                        "name": filename,
                                        "is_directory": is_dir,
                                        "attributes": attrs,
                                    }
                                )
                                # Mark success as soon as we have a parsed entry
                                # so a mid-enumeration error doesn't discard the
                                # files already collected.
                                result["success"] = True
                                self.logger.display(
                                    f"  {'[DIR]' if is_dir else '[FILE]'} {filename}"
                                )

                            except Exception as e:
                                # Error 1804 = no more files
                                if "1804" in str(e):
                                    break
                                raise

                        result["success"] = True

            finally:
                sys_conn.close()

        except Exception as e:
            self.logger.debug(f"File listing failed: {e}")
            result["error"] = str(e)

        self.logger.display(f"  Found {len(result['files'])} entries")
        return result

    def _read_file(self, path: str) -> Dict[str, Any]:
        """Read a file from target via SystemService (port 10000).

        Uses index groups:
        - 0x78 (FILE_OPEN): Open file
        - 0x7A (FILE_READ): Read from file
        - 0x79 (FILE_CLOSE): Close handle
        """
        result = {
            "success": False,
            "path": path,
            "size": 0,
            "data": None,
        }

        self.logger.display(f"Reading file: {path} (port 10000)...")
        pyads = _get_pyads()

        try:
            sys_conn = pyads.Connection(self.ams_netid, 10000)
            sys_conn.open()
            sys_conn.set_timeout(self.ads_timeout_ms)

            max_read = 65536
            max_file_size = 100 * 1024 * 1024  # 100MB

            def _open_handle() -> int:
                # Write: flags(4) + path, Read: handle(4)
                flags = ADS_FILE_FLAG["READ"] | ADS_FILE_FLAG["BINARY"]
                open_data = struct.pack("<I", flags) + path.encode("utf-8") + b"\x00"
                handle_data = _read_write_raw(sys_conn, ADS_IDX_GRP["FILE_OPEN"], 0, 4, open_data)
                if handle_data and len(handle_data) >= 4:
                    handle = struct.unpack("<I", handle_data)[0]
                    if handle > 0:
                        return handle
                return 0

            def _close_handle(handle: int) -> None:
                try:
                    _write_raw(sys_conn, ADS_IDX_GRP["FILE_CLOSE"], handle, b"")
                except Exception as e:
                    self.logger.debug("file close failed: %s", e)

            try:
                file_handle = _open_handle()
                self.logger.debug(f"  File handle: {file_handle}")

                if file_handle > 0:
                    # Pass 1 -- discover the size. FILE_READ is a sequential
                    # stream and _read_raw uses a fixed ctypes buffer, so the
                    # final partial chunk raises "Insufficient data (... M were
                    # read)". That chunk's bytes are gone (the stream position
                    # already advanced), so this pass only recovers whole 64KB
                    # chunks plus the reported tail length.
                    content = b""
                    total_size: Optional[int] = None
                    truncated = False
                    try:
                        while True:
                            chunk = _read_raw(
                                sys_conn, ADS_IDX_GRP["FILE_READ"], file_handle, max_read
                            )
                            if not chunk:
                                break
                            content += chunk
                            if len(content) >= max_file_size:
                                self.logger.warning(
                                    f"  File exceeds {max_file_size // (1024 * 1024)}MB "
                                    "limit, truncating"
                                )
                                truncated = True
                                break
                            if len(chunk) < max_read:
                                break
                    except RuntimeError as e:
                        m = re.search(r"(\d+)\s+were\s+read", str(e))
                        if m:
                            total_size = len(content) + int(m.group(1))
                        elif "1804" not in str(e) and "1797" not in str(e):
                            self.logger.debug(f"Read error: {e}")
                    except Exception as e:
                        if "1804" not in str(e) and "1797" not in str(e):
                            self.logger.debug(f"Read error: {e}")
                    _close_handle(file_handle)

                    # Pass 2 -- if a short final chunk truncated us, re-open and
                    # re-read in exact-sized chunks (the last sized to fit) so no
                    # read short-reads and the partial tail is recovered intact.
                    if not truncated and total_size is not None and total_size > len(content):
                        want = min(total_size, max_file_size)
                        handle2 = _open_handle()
                        if handle2 > 0:
                            try:
                                rebuilt = b""
                                remaining = want
                                while remaining > 0:
                                    n = min(max_read, remaining)
                                    part = _read_raw(sys_conn, ADS_IDX_GRP["FILE_READ"], handle2, n)
                                    if not part:
                                        break
                                    rebuilt += part
                                    remaining -= len(part)
                                content = rebuilt
                            except Exception as e:
                                self.logger.debug(f"File re-read failed: {e}")
                            _close_handle(handle2)

                    result["data"] = content
                    result["size"] = len(content)
                    result["success"] = bool(content) or total_size == 0
                    self.logger.success(f"  Read {len(content)} bytes")

            finally:
                sys_conn.close()

        except Exception as e:
            self.logger.debug(f"File read failed: {e}")
            result["error"] = str(e)

        return result

    def _delete_file_foe(self, port: int, filename: str) -> Dict[str, Any]:
        """Delete a file on an EtherCAT slave via FoE.

        FoE has no standard delete opcode.  Strategy:
        1. Open for write (0xF402) with the target filename.
        2. Close immediately (0xF403) without writing any data.
           On many firmwares this truncates / removes the file.

        Args:
            port: EtherCAT slave ADS port (e.g. 1001).
            filename: Remote filename to delete.

        Returns:
            Dict with success, error, hint keys.
        """
        result = {"success": False, "port": port, "filename": filename}
        pyads = _get_pyads()

        self.logger.display(f"FoE delete: port {port}, file '{filename}'")

        try:
            slave_conn = pyads.Connection(self.ams_netid, port)
            slave_conn.open()

            try:
                # Open for write — returns 4-byte handle
                handle_data = _read_write_raw(
                    slave_conn,
                    ADS_IDX_GRP["ECAT_FOE_OPEN_W"],
                    0,
                    4,
                    filename.encode("utf-8") + b"\x00",
                )

                if not handle_data or len(handle_data) < 4:
                    result["error"] = "Failed to open file for write (no handle)"
                    return result

                handle = struct.unpack("<I", handle_data[:4])[0]
                self.logger.debug(f"  FoE write handle: {handle}")

                # Close immediately — truncate / delete
                try:
                    _read_write_raw(
                        slave_conn,
                        ADS_IDX_GRP["ECAT_FOE_CLOSE"],
                        handle,
                        4,
                        b"",
                    )
                except Exception:
                    # Some devices don't return data on close
                    pass

                result["success"] = True
                result["hint"] = "File opened for write and closed (truncated)"
                self.logger.success(f"  FoE delete OK: '{filename}' on port {port}")

            finally:
                slave_conn.close()

        except Exception as e:
            err_code = _extract_ads_error_code(str(e))
            err_name = ADS_ERROR_CODES.get(err_code, "") if err_code else ""
            result["error"] = str(e)

            if err_code == 24:
                result["hint"] = "Invalid AMS port — not a real slave"
            elif err_code == 1793:
                result["hint"] = "FoE not supported on this slave"
            elif err_code == 1796:
                result["hint"] = "Access denied — slave may require Bootstrap state"
            elif err_code == 1823:
                result["hint"] = "Request aborted — file may not exist or FoE proxied by router"
            else:
                result["hint"] = err_name or "Unknown error"

            self.logger.fail(f"  FoE delete failed on port {port}: {err_name or e}")

        return result

    def _read_task_data(self) -> Dict[str, Any]:
        """Read PLC task runtime data via ig=0xF200 (TASK_DATA).

        Reads cycle times, execution statistics from the PLC runtime.
        Requires a connection to a PLC runtime port (e.g. 851).

        Returns:
            Dict with success, tasks list, error keys.
        """
        result = {"success": False, "tasks": []}
        pyads = _get_pyads()
        ads_port = self._get_ads_port()

        self.logger.display(f"Reading task data (ig=0xF200, port {ads_port})...")

        try:
            conn = pyads.Connection(self.ams_netid, ads_port)
            conn.open()
            conn.set_timeout(self.ads_timeout_ms)

            try:
                # Task data is organized by task index at offset.
                # Try reading task 0..7 — typical TwinCAT has 1-4 tasks.
                # Each task entry: cycle_time(4) + priority(4) + ...
                # The exact struct layout depends on TwinCAT version.
                # We probe with increasing offsets until we get an error.
                for task_idx in range(8):
                    try:
                        # Read 64 bytes from TASK_DATA at offset = task_idx
                        data = _read_raw(
                            conn,
                            ADS_IDX_GRP["TASK_DATA"],
                            task_idx,
                            64,
                        )

                        if not data or len(data) < 4:
                            break

                        # Check for router zero-fill
                        if data == b"\x00" * len(data):
                            self.logger.debug(f"  Task {task_idx}: zero-fill (router proxy)")
                            break

                        # Parse what we can: first 4 bytes are typically cycle time in 100ns units
                        task_info = {
                            "index": task_idx,
                            "raw_hex": data[:32].hex(),
                        }

                        # Try to extract cycle time (uint32, 100ns units)
                        if len(data) >= 4:
                            cycle_100ns = struct.unpack("<I", data[0:4])[0]
                            if cycle_100ns > 0:
                                task_info["cycle_time_us"] = cycle_100ns / 10.0
                                task_info["cycle_time_ms"] = cycle_100ns / 10000.0

                        # Priority (uint32) at offset 4
                        if len(data) >= 8:
                            priority = struct.unpack("<I", data[4:8])[0]
                            task_info["priority"] = priority

                        result["tasks"].append(task_info)
                        self.logger.display(
                            f"  Task {task_idx}: "
                            + (
                                f"cycle={task_info.get('cycle_time_ms', '?')}ms, "
                                f"prio={task_info.get('priority', '?')}"
                                if task_info.get("cycle_time_us")
                                else f"raw={data[:16].hex()}"
                            )
                        )

                    except Exception as e:
                        err_code = _extract_ads_error_code(str(e))
                        if err_code in (0x0702, 0x0703, 0x0701):
                            # Invalid group/offset/service — no more tasks
                            break
                        self.logger.debug(f"  Task {task_idx}: {e}")
                        break

                result["success"] = len(result["tasks"]) > 0

            finally:
                conn.close()

        except Exception as e:
            self.logger.debug(f"Task data read failed: {e}")
            result["error"] = str(e)

        if not result["tasks"]:
            self.logger.display("  No task data available (ig=0xF200 not supported on this port)")

        return result

    def _read_registry(self, hive: str, key: str, value: str = None) -> Dict[str, Any]:
        """Read Windows registry via SystemService (port 10000).

        Uses index groups:
        - 0xC8 (REG_HKLM): HKEY_LOCAL_MACHINE
        - 0xC9 (REG_HKCU): HKEY_CURRENT_USER
        - 0xCA (REG_HKCR): HKEY_CLASSES_ROOT
        """
        result = {
            "success": False,
            "hive": hive,
            "key": key,
            "value": value,
            "data": None,
            "type": None,
        }

        hive_map = {
            "HKLM": ADS_IDX_GRP["REG_HKLM"],
            "HKEY_LOCAL_MACHINE": ADS_IDX_GRP["REG_HKLM"],
            "HKCU": ADS_IDX_GRP["REG_HKCU"],
            "HKEY_CURRENT_USER": ADS_IDX_GRP["REG_HKCU"],
            "HKCR": ADS_IDX_GRP["REG_HKCR"],
            "HKEY_CLASSES_ROOT": ADS_IDX_GRP["REG_HKCR"],
        }

        index_group = hive_map.get(hive.upper())
        if not index_group:
            result["error"] = f"Unknown hive: {hive}"
            return result

        self.logger.display(f"Reading registry: {hive}\\{key}")
        pyads = _get_pyads()

        try:
            sys_conn = pyads.Connection(self.ams_netid, 10000)
            sys_conn.open()
            sys_conn.set_timeout(self.ads_timeout_ms)

            try:
                # Build registry path
                if value:
                    reg_path = f"{key}\\{value}\x00"
                else:
                    reg_path = f"{key}\x00"

                # Query registry (returns type + data)
                reg_data = _read_write_raw(
                    sys_conn,
                    index_group,
                    0,
                    4096,  # Max buffer
                    reg_path.encode("utf-8"),
                )

                if reg_data and len(reg_data) >= 4:
                    # First 4 bytes are type
                    reg_type = struct.unpack("<I", reg_data[:4])[0]
                    reg_value = reg_data[4:]

                    result["type"] = reg_type
                    result["data"] = reg_value
                    result["success"] = True

                    # Parse based on type
                    type_names = {
                        1: "REG_SZ",
                        2: "REG_EXPAND_SZ",
                        3: "REG_BINARY",
                        4: "REG_DWORD",
                        7: "REG_MULTI_SZ",
                        11: "REG_QWORD",
                    }
                    type_name = type_names.get(reg_type, f"TYPE_{reg_type}")

                    if reg_type in (1, 2, 7):  # String types
                        decoded = reg_value.decode("utf-16-le", errors="ignore").rstrip("\x00")
                        result["decoded"] = decoded
                        self.logger.success(f"  {type_name}: {decoded}")
                    elif reg_type == 4:  # DWORD
                        if len(reg_value) >= 4:
                            dword = struct.unpack("<I", reg_value[:4])[0]
                            result["decoded"] = dword
                            self.logger.success(f"  {type_name}: {dword} (0x{dword:08x})")
                    else:
                        self.logger.success(f"  {type_name}: {reg_value.hex()}")

            finally:
                sys_conn.close()

        except Exception as e:
            self.logger.debug(f"Registry read failed: {e}")
            result["error"] = str(e)

        return result

    def _add_route(self, netid: str, ip: str, route_name: str = "route") -> Dict[str, Any]:
        """Add an AMS route via SystemService (port 10000).

        Uses index group 0x321 (ROUTE_ADD).
        This creates a routing entry allowing ADS communication to a new target.

        WARNING: This modifies the target system's routing table.
        """
        result = {
            "success": False,
            "netid": netid,
            "ip": ip,
            "route_name": route_name,
        }

        self.logger.display(f"Adding route: {netid} -> {ip} (name: {route_name})")
        pyads = _get_pyads()

        try:
            sys_conn = pyads.Connection(self.ams_netid, 10000)
            sys_conn.open()
            sys_conn.set_timeout(self.ads_timeout_ms)

            try:
                # Parse NetID
                netid_parts = [int(x) for x in netid.split(".")]
                if len(netid_parts) != 6:
                    result["error"] = "Invalid NetID format (expected x.x.x.x.x.x)"
                    return result

                # Build route entry
                # Format: flags(4) + netid(6) + port(2) + ip_len(4) + ip + name_len(4) + name
                flags = 0x00000001  # Permanent route
                netid_bytes = bytes(netid_parts)
                port = 48898
                ip_bytes = ip.encode("utf-8") + b"\x00"
                name_bytes = route_name.encode("utf-8") + b"\x00"

                route_data = struct.pack("<I", flags)
                route_data += netid_bytes
                route_data += struct.pack("<H", port)
                route_data += struct.pack("<I", len(ip_bytes)) + ip_bytes
                route_data += struct.pack("<I", len(name_bytes)) + name_bytes

                # Write route
                _write_raw(sys_conn, ADS_IDX_GRP["ROUTE_ADD"], 0, route_data)
                result["success"] = True
                self.logger.success("  Route added successfully")

            finally:
                sys_conn.close()

        except Exception as e:
            self.logger.debug(f"Route add failed: {e}")
            result["error"] = str(e)

        return result

    def _download_plc_program(self, connection: Any) -> Dict[str, Any]:
        """Download PLC symbol/program information.

        Uses index groups:
        - 0xF00C (SYM_UPLOAD_INFO): Get upload info (sizes)
        - 0xF00B (SYM_UPLOAD): Upload symbol table
        - 0xF00E (SYM_DTYPE_UPLOAD): Upload data types
        """
        result = {
            "success": False,
            "symbol_count": 0,
            "symbol_size": 0,
            "datatype_size": 0,
            "symbols": None,
            "datatypes": None,
        }

        self.logger.display("Downloading PLC program information...")

        try:
            # Get upload info first
            info_data = _read_raw(connection, ADS_IDX_GRP["SYM_UPLOAD_INFO"], 0, 24)
            if info_data and len(info_data) >= 24:
                symbol_count = struct.unpack("<I", info_data[0:4])[0]
                symbol_size = struct.unpack("<I", info_data[4:8])[0]
                datatype_size = struct.unpack("<I", info_data[8:12])[0]

                result["symbol_count"] = symbol_count
                result["symbol_size"] = symbol_size
                result["datatype_size"] = datatype_size

                self.logger.display(f"  Symbols: {symbol_count} ({symbol_size} bytes)")
                self.logger.display(f"  Datatypes: {datatype_size} bytes")

                # Download symbol table
                if symbol_size > 0 and symbol_size < 10000000:  # 10MB limit
                    try:
                        symbols = _read_raw(connection, ADS_IDX_GRP["SYM_UPLOAD"], 0, symbol_size)
                        result["symbols"] = symbols
                        self.logger.success(f"  Downloaded {len(symbols)} bytes of symbols")
                    except Exception as e:
                        self.logger.debug(f"Symbol download failed: {e}")

                # Download datatypes
                if datatype_size > 0 and datatype_size < 10000000:
                    try:
                        datatypes = _read_raw(
                            connection, ADS_IDX_GRP["SYM_DTYPE_UPLOAD"], 0, datatype_size
                        )
                        result["datatypes"] = datatypes
                        self.logger.success(f"  Downloaded {len(datatypes)} bytes of datatypes")
                    except Exception as e:
                        self.logger.debug(f"Datatype download failed: {e}")

                result["success"] = True

        except Exception as e:
            self.logger.debug(f"Program download failed: {e}")
            result["error"] = str(e)

        return result

    def _scan_ethercat(self) -> Dict[str, Any]:
        """Scan EtherCAT master and slaves via ADS.

        Connects to the EtherCAT master (AMS port 0xFFFF) to read:
        - Slave count (ig=0x0006, offset=0)
        - Master AL state (ig=0x0009, offset=0)
        - Slave identity objects (ig=0x0011, offset=slave_port)
        - Slave AL states (ig=0x0009, offset=slave_port)

        Then connects to each slave port (1001+) to read CoE SDOs:
        - Device name (0x1008:0), HW version (0x1009:0), SW version (0x100A:0)
        """
        result = {
            "success": False,
            "master_state": None,
            "slave_count": 0,
            "slaves": [],
        }

        self.logger.display("Scanning EtherCAT configuration...")
        pyads = _get_pyads()
        self.logger.debug(f"EtherCAT scan starting on AMS Net ID {self.ams_netid}")

        try:
            # --- Connect to EtherCAT master (port 0xFFFF = 65535) ---
            master_conn = pyads.Connection(self.ams_netid, 0xFFFF)
            master_conn.open()
            master_conn.set_timeout(self.ads_timeout_ms)
            self.logger.debug(
                f"Master connection opened on port 0xFFFF, timeout={self.ads_timeout_ms}ms"
            )

            try:
                # Read master AL state (ig=0x0009, offset=0, 2 bytes)
                self.logger.debug(
                    f"Reading master AL state: ig=0x{ADS_IDX_GRP['ECAT_AL_STATE']:04X}, offset=0, size=2"
                )
                try:
                    state_data = _read_raw(master_conn, ADS_IDX_GRP["ECAT_AL_STATE"], 0, 2)
                    if state_data and len(state_data) >= 2:
                        raw_state = struct.unpack("<H", state_data)[0]
                        state_name = get_al_state_name(raw_state)
                        result["master_state"] = state_name
                        self.logger.debug(f"Master AL state raw=0x{raw_state:04X} → {state_name}")
                        self.logger.display(f"  EtherCAT Master State: {state_name}")
                except Exception as e:
                    self.logger.debug(f"Master state read failed: {e}")

                # Read slave count (ig=0x0006, offset=0, 2 bytes)
                slave_count = 0
                self.logger.debug(
                    f"Reading slave count: ig=0x{ADS_IDX_GRP['ECAT_SLAVE_COUNT']:04X}, offset=0, size=2"
                )
                try:
                    count_data = _read_raw(master_conn, ADS_IDX_GRP["ECAT_SLAVE_COUNT"], 0, 2)
                    if count_data and len(count_data) >= 2:
                        slave_count = struct.unpack("<H", count_data)[0]
                        result["slave_count"] = slave_count
                        self.logger.debug(f"Slave count = {slave_count}")
                except Exception as e:
                    self.logger.debug(f"Slave count read failed: {e}")

                if slave_count == 0:
                    self.logger.display("  No EtherCAT slaves found")
                    result["success"] = True
                    return result

                # Sanity-clamp the device-reported count: it is attacker-controlled
                # and drives an unbounded per-slave network loop below. The EtherCAT
                # spec allows up to 65535 slaves, but a real segment is far smaller;
                # clamp to MAX_SLAVE_PORTS to avoid a self-inflicted scanner DoS.
                if slave_count > MAX_SLAVE_PORTS:
                    self.logger.warning(
                        f"  Device reported {slave_count} slaves — clamping scan to "
                        f"{MAX_SLAVE_PORTS} (implausible count, possible spoofing)"
                    )
                    slave_count = MAX_SLAVE_PORTS

                self.logger.display(f"  EtherCAT slaves: {slave_count}")

                # Determine slave port range: first port from ig=0x0007
                first_port = 1001
                self.logger.debug(
                    f"Reading first port: ig=0x{ADS_IDX_GRP['ECAT_FIRST_PORT']:04X}, offset=0, size=2"
                )
                try:
                    fp_data = _read_raw(master_conn, ADS_IDX_GRP["ECAT_FIRST_PORT"], 0, 2)
                    if fp_data and len(fp_data) >= 2:
                        first_port = struct.unpack("<H", fp_data)[0]
                        self.logger.debug(f"First slave port = {first_port}")
                except Exception as e:
                    self.logger.debug(f"First port read failed, assuming 1001: {e}")

                slave_ports = list(range(first_port, first_port + slave_count))
                self.logger.debug(
                    f"Slave port range: {slave_ports[0]}-{slave_ports[-1]} ({len(slave_ports)} ports)"
                )

                # --- Read identity and state for each slave from master port ---
                self.logger.debug("Reading identity and AL state for each slave via master port")
                for port in slave_ports:
                    slave_info = {"port": port}

                    # Identity object (ig=0x0011, offset=slave_port, 16 bytes)
                    # Layout: vendor_id(4) + product_code(4) + revision(4) + serial(4)
                    try:
                        ident_data = _read_raw(
                            master_conn, ADS_IDX_GRP["ECAT_SLAVE_IDENT"], port, 16
                        )
                        if ident_data and len(ident_data) >= 16:
                            vendor, product, revision, serial = struct.unpack(
                                "<IIII", ident_data[:16]
                            )
                            slave_info["vendor_id"] = f"0x{vendor:08X}"
                            slave_info["vendor_name"] = lookup_vendor(vendor)
                            slave_info["product_code"] = f"0x{product:08X}"
                            slave_info["revision"] = f"0x{revision:08X}"
                            slave_info["serial"] = f"0x{serial:08X}"
                            self.logger.debug(
                                f"Slave {port} identity: vendor=0x{vendor:08X} "
                                f"({lookup_vendor(vendor)}), product=0x{product:08X}, "
                                f"revision=0x{revision:08X}, serial=0x{serial:08X}"
                            )
                        else:
                            self.logger.debug(f"Slave {port} identity: no data or short response")
                    except Exception as e:
                        self.logger.debug(f"Slave {port} identity read failed: {e}")

                    # AL state (ig=0x0009, offset=slave_port, 2 bytes)
                    try:
                        state_data = _read_raw(master_conn, ADS_IDX_GRP["ECAT_AL_STATE"], port, 2)
                        if state_data and len(state_data) >= 2:
                            raw_state = struct.unpack("<H", state_data)[0]
                            state_name = get_al_state_name(raw_state)
                            slave_info["al_state"] = state_name
                            self.logger.debug(
                                f"Slave {port} AL state: raw=0x{raw_state:04X} → {state_name}"
                            )
                    except Exception as e:
                        self.logger.debug(f"Slave {port} state read failed: {e}")

                    result["slaves"].append(slave_info)

                # --- Read CoE SDOs from each slave's own port ---
                self.logger.debug(
                    "Reading CoE SDO strings (device name, HW/SW version) from each slave port"
                )
                for slave_info in result["slaves"]:
                    port = slave_info["port"]
                    slave_conn = None
                    try:
                        slave_conn = pyads.Connection(self.ams_netid, port)
                        slave_conn.open()
                        slave_conn.set_timeout(self.ads_timeout_ms)
                        self.logger.debug(
                            f"Slave {port}: CoE connection opened, timeout={self.ads_timeout_ms}ms"
                        )

                        for sdo_name, sdo_key in [
                            ("device_name", "DEVICE_NAME"),
                            ("hw_version", "HW_VERSION"),
                            ("sw_version", "SW_VERSION"),
                        ]:
                            try:
                                value = _read_coe_string(
                                    slave_conn,
                                    ADS_IDX_GRP["COE_SDO"],
                                    COE_SDO_OFFSET[sdo_key],
                                )
                                if value:
                                    slave_info[sdo_name] = value
                                    self.logger.debug(f"Slave {port} {sdo_name}: {repr(value)}")
                                else:
                                    self.logger.debug(f"Slave {port} {sdo_name}: empty/no data")
                            except Exception as e:
                                self.logger.debug(f"Slave {port} {sdo_name} failed: {e}")

                    except Exception as e:
                        self.logger.debug(f"Slave {port} CoE connection failed: {e}")
                    finally:
                        if slave_conn:
                            try:
                                slave_conn.close()
                            except Exception as e:
                                self.logger.debug(f"slave_conn.close(): {e}")

                result["success"] = True
                self.logger.debug(
                    f"EtherCAT scan complete: {len(result['slaves'])} slaves discovered"
                )

            finally:
                master_conn.close()
                self.logger.debug("Master connection closed")

        except Exception as e:
            self.logger.debug(f"EtherCAT scan failed: {e}")
            result["error"] = str(e)

        return result

    # Delegates to shared coe.py — kept as a static method for backward compat
    _parse_coe_ranges = staticmethod(parse_coe_ranges)

    def _scan_coe_via_ads(self, slave_ports, test_access=False, scan_ranges=None):
        """Scan full CoE object dictionary for EtherCAT slaves via ADS bridge.

        Opens a pyads connection to each slave port and iterates the given
        scan ranges (defaulting to COE_SCAN_RANGES), reading each
        index/subindex with _read_coe_sdo().

        Args:
            slave_ports: List of ADS slave port numbers (e.g. [1001, 1002, ...])
            test_access: If True, test write access on each object (requires --confirm)
            scan_ranges: Override COE_SCAN_RANGES with custom list of (start, end, label)

        Returns:
            Dict mapping port number to list of object dicts.
        """
        pyads = _get_pyads()
        results = {}
        raw_ranges = scan_ranges if scan_ranges is not None else COE_SCAN_RANGES
        # Normalize to 4-tuples: (start, end, label, subs)
        # COE_SCAN_RANGES has 3-tuples, _parse_coe_ranges returns 4-tuples
        ranges = [r if len(r) == 4 else (r[0], r[1], r[2], None) for r in raw_ranges]

        for port in slave_ports:
            label = "CoE dictionary + access" if test_access else "CoE dictionary"
            self.logger.display(f"  Scanning {label} on port {port}...")
            slave_conn = None
            objects = []
            access_stats = {"RO": 0, "RW": 0, "WO": 0}
            sdo_info_cache = {}  # (idx, sub) -> name or None
            sdo_info_available = None  # None=untested, True/False

            def _get_device_name(conn, idx, sub):
                """Get object name from device via SDO Info (ig=0xF3FE)."""
                nonlocal sdo_info_available
                key = (idx, sub)
                if key in sdo_info_cache:
                    return sdo_info_cache[key]
                if sdo_info_available is False:
                    sdo_info_cache[key] = None
                    return None
                desc = _read_sdo_entry_desc(conn, idx, sub)
                if desc and desc["name"]:
                    name = desc["name"]
                    if name.startswith("SubIndex "):
                        name = None
                    sdo_info_cache[key] = name
                    if sdo_info_available is None:
                        sdo_info_available = True
                    return name
                sdo_info_cache[key] = None
                if sdo_info_available is None:
                    sdo_info_available = False
                return None

            def _resolve_name(conn, idx, sub):
                """Resolve object name: device first, then static table."""
                device_name = _get_device_name(conn, idx, sub)
                return device_name if device_name else get_coe_object_name(idx, sub)

            try:
                slave_conn = pyads.Connection(self.ams_netid, port)
                slave_conn.open()
                slave_conn.set_timeout(self.ads_timeout_ms)
                self.logger.debug(
                    f"Port {port}: connection opened, timeout={self.ads_timeout_ms}ms"
                )

                total_indices = sum(end - start for start, end, _, _s in ranges)
                self.logger.debug(
                    f"Port {port}: scanning {len(ranges)} ranges ({total_indices} indices)"
                    f"{' + access testing' if test_access else ''}"
                )

                progress = ProgressTracker(
                    total_indices,
                    threshold=1.0,
                    interval=0.5,
                    logger=self.logger,
                    show=True,
                )

                for start, end, category, filter_subs in ranges:
                    range_found = 0
                    self.logger.debug(
                        f"Port {port}: range 0x{start:04X}-0x{end:04X} ({end - start} indices) [{category}]"
                    )
                    for idx in range(start, end):
                        progress.update()
                        # When filter_subs is set, skip sub0 discovery and
                        # only read the specific subindices requested
                        if filter_subs is not None:
                            self.logger.debug(
                                f"  0x{idx:04X}: reading specific subindices {filter_subs}"
                            )
                            for sub in filter_subs:
                                sdata = _read_coe_sdo(slave_conn, idx, sub)
                                if sdata is None:
                                    if test_access:
                                        wo_ok, _ = _write_coe_sdo(slave_conn, idx, sub, b"\x00")
                                        if wo_ok:
                                            sub_name = _resolve_name(slave_conn, idx, sub)
                                            sub_obj = {
                                                "index": f"0x{idx:04X}",
                                                "subindex": sub,
                                                "name": sub_name,
                                                "size": 0,
                                                "data": "",
                                                "category": category,
                                                "access": "WO",
                                            }
                                            objects.append(sub_obj)
                                            access_stats["WO"] += 1
                                            range_found += 1
                                            self.logger.debug(f"    :{sub} WO ({sub_name})")
                                    continue
                                sub_name = _resolve_name(slave_conn, idx, sub)
                                sub_access_tag = ""
                                sub_obj = {
                                    "index": f"0x{idx:04X}",
                                    "subindex": sub,
                                    "name": sub_name,
                                    "size": len(sdata),
                                    "data": sdata.hex(),
                                    "category": category,
                                }
                                if len(sdata) <= 4:
                                    sub_obj["value"] = int.from_bytes(sdata, "little")
                                if test_access:
                                    writable, write_err = _write_coe_sdo(
                                        slave_conn, idx, sub, sdata
                                    )
                                    if writable:
                                        sub_obj["access"] = "RW"
                                        access_stats["RW"] += 1
                                        sub_access_tag = " RW"
                                    else:
                                        sub_obj["access"] = "RO"
                                        access_stats["RO"] += 1
                                        sub_access_tag = " RO"
                                        self.logger.debug(
                                            f"    :{sub} write-back rejected: {write_err}"
                                        )
                                objects.append(sub_obj)
                                range_found += 1
                                self.logger.debug(
                                    f"    :{sub} ({sub_name}) {len(sdata)}B "
                                    f"{sdata.hex()[:16]}{'...' if len(sdata) > 8 else ''}"
                                    f"{sub_access_tag}"
                                )
                            continue

                        data = _read_coe_sdo(slave_conn, idx, 0)

                        if data is None:
                            # Object not readable — test write-only if access mode
                            if test_access:
                                wo_ok, _ = _write_coe_sdo(slave_conn, idx, 0, b"\x00")
                                if wo_ok:
                                    name = _resolve_name(slave_conn, idx, 0)
                                    obj = {
                                        "index": f"0x{idx:04X}",
                                        "subindex": 0,
                                        "name": name,
                                        "size": 0,
                                        "data": "",
                                        "category": category,
                                        "access": "WO",
                                    }
                                    objects.append(obj)
                                    access_stats["WO"] += 1
                                    range_found += 1
                                    self.logger.debug(f"  0x{idx:04X}:0 WO ({name})")
                            continue

                        name = _resolve_name(slave_conn, idx, 0)
                        access_tag = ""
                        obj = {
                            "index": f"0x{idx:04X}",
                            "subindex": 0,
                            "name": name,
                            "size": len(data),
                            "data": data.hex(),
                            "category": category,
                        }
                        if len(data) <= 4:
                            obj["value"] = int.from_bytes(data, "little")

                        if test_access:
                            writable, write_err = _write_coe_sdo(slave_conn, idx, 0, data)
                            if writable:
                                obj["access"] = "RW"
                                access_stats["RW"] += 1
                                access_tag = " RW"
                            else:
                                obj["access"] = "RO"
                                access_stats["RO"] += 1
                                access_tag = " RO"
                                self.logger.debug(
                                    f"  0x{idx:04X}:0 write-back rejected: {write_err}"
                                )

                        objects.append(obj)
                        range_found += 1
                        self.logger.debug(
                            f"  0x{idx:04X}:0 ({name}) {len(data)}B {data.hex()[:16]}"
                            f"{'...' if len(data) > 8 else ''}{access_tag}"
                        )

                        # Scan subindices: use sub0 as count if 1..32,
                        # else probe sub1 as fallback (some objects like 0xFB00
                        # have sub0=0 yet sub1+ contain data)
                        max_sub = data[0] if len(data) == 1 and 0 < data[0] <= 32 else 0
                        sub1_data = None
                        if max_sub == 0:
                            sub1_data = _read_coe_sdo(slave_conn, idx, 1)
                            if sub1_data is not None:
                                max_sub = (
                                    32  # unknown count — scan up to 32, rely on consecutive_fail
                                )
                                self.logger.debug(
                                    f"  0x{idx:04X}: sub0 not a count, but sub1 exists — probing up to 32"
                                )
                        if max_sub > 0:
                            self.logger.debug(
                                f"  0x{idx:04X}: scanning subindices 1..{min(max_sub, 32)}"
                            )
                            sub_found = 0
                            consecutive_fail = 0
                            for sub in range(1, min(max_sub + 1, 33)):
                                if sub == 1 and sub1_data is not None:
                                    sdata = sub1_data
                                else:
                                    sdata = _read_coe_sdo(slave_conn, idx, sub)
                                if sdata is None:
                                    if test_access:
                                        wo_ok, _ = _write_coe_sdo(slave_conn, idx, sub, b"\x00")
                                        if wo_ok:
                                            sub_name = _resolve_name(slave_conn, idx, sub)
                                            sub_obj = {
                                                "index": f"0x{idx:04X}",
                                                "subindex": sub,
                                                "name": sub_name,
                                                "size": 0,
                                                "data": "",
                                                "category": category,
                                                "access": "WO",
                                            }
                                            objects.append(sub_obj)
                                            access_stats["WO"] += 1
                                            sub_found += 1
                                            consecutive_fail = 0
                                            self.logger.debug(f"    :{sub} WO ({sub_name})")
                                            continue
                                    consecutive_fail += 1
                                    if consecutive_fail >= 3:
                                        self.logger.debug(
                                            f"    :{sub} 3 consecutive misses, stopping subindex scan"
                                        )
                                        break
                                    continue
                                consecutive_fail = 0
                                sub_name = _resolve_name(slave_conn, idx, sub)
                                sub_access_tag = ""
                                sub_obj = {
                                    "index": f"0x{idx:04X}",
                                    "subindex": sub,
                                    "name": sub_name,
                                    "size": len(sdata),
                                    "data": sdata.hex(),
                                    "category": category,
                                }
                                if len(sdata) <= 4:
                                    sub_obj["value"] = int.from_bytes(sdata, "little")

                                if test_access:
                                    writable, write_err = _write_coe_sdo(
                                        slave_conn, idx, sub, sdata
                                    )
                                    if writable:
                                        sub_obj["access"] = "RW"
                                        access_stats["RW"] += 1
                                        sub_access_tag = " RW"
                                    else:
                                        sub_obj["access"] = "RO"
                                        access_stats["RO"] += 1
                                        sub_access_tag = " RO"
                                        self.logger.debug(
                                            f"    :{sub} write-back rejected: {write_err}"
                                        )

                                objects.append(sub_obj)
                                sub_found += 1
                                self.logger.debug(
                                    f"    :{sub} ({sub_name}) {len(sdata)}B "
                                    f"{sdata.hex()[:16]}{'...' if len(sdata) > 8 else ''}{sub_access_tag}"
                                )
                            self.logger.debug(f"  0x{idx:04X}: {sub_found} subindices found")

                    if range_found:
                        self.logger.debug(
                            f"Port {port}: range [{category}] 0x{start:04X}-0x{end:04X}: "
                            f"{range_found} objects found"
                        )

                progress.finish()

            except Exception as e:
                self.logger.debug(f"CoE scan port {port} failed: {e}")
            finally:
                if slave_conn:
                    try:
                        slave_conn.close()
                    except Exception as e:
                        logger.debug(f"slave_conn.close(): {e}")

            results[port] = objects
            if sdo_info_available:
                src = "device SDO Info"
            else:
                src = "static lookup tables"
            if test_access:
                total = access_stats["RO"] + access_stats["RW"] + access_stats["WO"]
                self.logger.display(
                    f"    Found {total} objects: "
                    f"{access_stats['RO']} RO, {access_stats['RW']} RW, {access_stats['WO']} WO"
                    f" (names from {src})"
                )
            else:
                self.logger.display(
                    f"    Found {len(objects)} objects on port {port} (names from {src})"
                )

        return results

    def _read_eeprom_word(self, master_conn, slave_port, word_addr):
        """Read a single EEPROM word (2 bytes) from a slave via ADS master port.

        Encoding: offset = (slave_port << 16) | word_addr
        """
        offset = (slave_port << 16) | word_addr
        try:
            return _read_raw(master_conn, ADS_IDX_GRP["ECAT_EEPROM_READ"], offset, 2)
        except Exception as e:
            self.logger.debug(f"EEPROM word read failed: {e}")
            return None

    def _dump_eeprom_via_ads(self, slave_ports):
        """Dump raw EEPROM contents from EtherCAT slaves via ADS master port.

        Reads 128 words (256 bytes) per slave. Stops on 3 consecutive failures.
        Parses SII header fields (vendor, product, revision, serial, alias).

        Args:
            slave_ports: List of ADS slave port numbers

        Returns:
            Dict mapping port to {words: [(addr, hex)], header: {parsed fields}}
        """
        pyads = _get_pyads()
        results = {}

        master_conn = None
        try:
            master_conn = pyads.Connection(self.ams_netid, 0xFFFF)
            master_conn.open()
            master_conn.set_timeout(self.ads_timeout_ms)
            self.logger.debug(
                f"EEPROM dump: master connection opened, timeout={self.ads_timeout_ms}ms, "
                f"{len(slave_ports)} slaves to read"
            )

            for port in slave_ports:
                self.logger.display(f"  Dumping EEPROM on slave port {port}...")
                words = []
                raw_data = bytearray()
                consecutive_fail = 0
                eeprom_progress = ProgressTracker(
                    0x0080,
                    threshold=1.0,
                    interval=0.5,
                    logger=self.logger,
                    show=True,
                )

                for addr in range(0x0080):  # 128 words = 256 bytes
                    eeprom_progress.update()
                    data = self._read_eeprom_word(master_conn, port, addr)
                    if data is None:
                        consecutive_fail += 1
                        raw_data.extend(b"\x00\x00")
                        if consecutive_fail >= 3:
                            self.logger.debug(
                                f"Slave {port}: 3 consecutive EEPROM read failures at word 0x{addr:04X}, stopping"
                            )
                            break
                        continue
                    consecutive_fail = 0
                    words.append({"address": f"0x{addr:04X}", "data": data.hex()})
                    raw_data.extend(data)

                eeprom_progress.finish()

                # Parse SII header — full parse (>=128B) or fallback (>=32B)
                header = {}
                raw_bytes = bytes(raw_data)
                if len(raw_bytes) >= 128:
                    header = parse_sii_header(raw_bytes)
                    # Alias for backward compat with display code
                    header["serial"] = header.get("serial_number", 0)
                elif len(raw_bytes) >= 32:
                    try:
                        header["station_alias"] = struct.unpack_from("<H", raw_bytes, 0x08)[0]
                        header["vendor_id"] = struct.unpack_from("<I", raw_bytes, 0x10)[0]
                        header["product_code"] = struct.unpack_from("<I", raw_bytes, 0x14)[0]
                        header["revision"] = struct.unpack_from("<I", raw_bytes, 0x18)[0]
                        header["serial"] = struct.unpack_from("<I", raw_bytes, 0x1C)[0]
                    except struct.error as e:
                        self.logger.debug(f"SII header fallback parse failed: {e}")

                results[port] = {
                    "words": words,
                    "header": header,
                }

                if words:
                    self.logger.display(
                        f"    Read {len(words)} EEPROM words ({len(words) * 2} bytes)"
                    )
                    if header:
                        self.logger.debug(
                            f"Slave {port} SII header: vendor=0x{header.get('vendor_id', 0):08X}, "
                            f"product=0x{header.get('product_code', 0):08X}, "
                            f"revision=0x{header.get('revision', 0):08X}, "
                            f"serial=0x{header.get('serial', 0):08X}, "
                            f"alias={header.get('station_alias', 0)}"
                        )
                else:
                    self.logger.display("    No EEPROM data (ig=0x000E may not be supported)")

        except Exception as e:
            self.logger.debug(f"EEPROM dump failed: {e}")
        finally:
            if master_conn:
                try:
                    master_conn.close()
                except Exception as e:
                    self.logger.debug(f"master_conn.close(): {e}")

        return results

    def _read_esc_registers_via_ads(self, slave_ports):
        """Read ESC registers from EtherCAT slaves via ADS bridge (ig=0xF300).

        Connects to each slave port and reads all registers in ESC_REGISTER_MAP.
        Decodes AL Status, SyncManager, FMMU, and DC fields structurally.

        Args:
            slave_ports: List of ADS slave port numbers

        Returns:
            Dict mapping port to register data.
        """
        pyads = _get_pyads()
        results = {}

        for port in slave_ports:
            self.logger.display(f"  Reading ESC registers on port {port}...")
            slave_conn = None
            registers = {}
            try:
                slave_conn = pyads.Connection(self.ams_netid, port)
                slave_conn.open()
                slave_conn.set_timeout(self.ads_timeout_ms)

                # Probe: read AL Status (2B register) with 256B buffer.
                # Real ESC returns short-read error; AMS router returns 256 zero bytes.
                try:
                    probe = _read_raw(slave_conn, ADS_IDX_GRP["ECAT_ESC_REG"], 0x0130, 256)
                    if len(probe) == 256 and probe == b"\x00" * 256:
                        self.logger.display(
                            f"    Port {port}: ESC register access not supported "
                            f"(AMS router zero-fill detected)"
                        )
                        results[port] = {"error": "ESC registers not supported (router zeros)"}
                        continue
                except RuntimeError as e:
                    self.logger.debug(f"Failed to get probe: {e}")  # Short-read = real ESC, proceed
                except Exception as e:
                    if _is_ads_timeout(str(e)):
                        self.logger.display(f"    Port {port}: timeout")
                        results[port] = {"error": "timeout"}
                        continue
                    # Other errors (e.g., error 24) — not supported
                    self.logger.display(f"    Port {port}: {e}")
                    results[port] = {"error": str(e)}
                    continue

                progress = ProgressTracker(
                    len(ESC_REGISTER_MAP),
                    threshold=1.0,
                    interval=0.5,
                    logger=self.logger,
                    show=True,
                )

                for addr, (name, size) in sorted(ESC_REGISTER_MAP.items()):
                    progress.update()
                    try:
                        data = _read_raw(slave_conn, ADS_IDX_GRP["ECAT_ESC_REG"], addr, size)
                    except RuntimeError as e:
                        m = re.search(r"(\d+)\s+were\s+read", str(e))
                        if m:
                            actual = int(m.group(1))
                            if actual > 0:
                                data = _read_raw(
                                    slave_conn, ADS_IDX_GRP["ECAT_ESC_REG"], addr, actual
                                )
                            else:
                                data = None
                        else:
                            data = None
                    except Exception:
                        data = None

                    if data is None:
                        continue

                    reg_entry = {
                        "name": name,
                        "address": f"0x{addr:04X}",
                        "size": size,
                        "data": data.hex(),
                    }

                    # Decode scalar values
                    if size <= 4:
                        val = int.from_bytes(data[:size], "little")
                        reg_entry["value"] = val

                    registers[addr] = reg_entry

                progress.finish()

                # Post-process: decode AL Status
                port_result = {"registers": registers}
                if 0x0130 in registers and "value" in registers[0x0130]:
                    al_val = registers[0x0130]["value"]
                    port_result["al_state"] = get_al_state_name(al_val & 0x0F)
                    port_result["al_error_flag"] = bool(al_val & 0x10)
                if 0x0134 in registers and "value" in registers[0x0134]:
                    port_result["al_status_code"] = get_al_status_error(registers[0x0134]["value"])

                # Decode SyncManagers
                sync_managers = []
                for sm_idx in range(4):
                    sm_addr = 0x0800 + (sm_idx * 8)
                    if sm_addr in registers and len(bytes.fromhex(registers[sm_addr]["data"])) >= 8:
                        sm_raw = bytes.fromhex(registers[sm_addr]["data"])
                        sm_start = struct.unpack_from("<H", sm_raw, 0)[0]
                        sm_len = struct.unpack_from("<H", sm_raw, 2)[0]
                        sm_ctrl = sm_raw[4]
                        sm_status = sm_raw[5]
                        sm_activate = sm_raw[6]
                        sync_managers.append(
                            {
                                "sm": sm_idx,
                                "start": f"0x{sm_start:04X}",
                                "length": sm_len,
                                "control": f"0x{sm_ctrl:02X}",
                                "status": f"0x{sm_status:02X}",
                                "activate": sm_activate,
                            }
                        )
                if sync_managers:
                    port_result["sync_managers"] = sync_managers

                results[port] = port_result
                self.logger.display(f"    Read {len(registers)} registers")

            except Exception as e:
                self.logger.debug(f"ESC register read failed on port {port}: {e}")
                results[port] = {"error": str(e)}
            finally:
                if slave_conn:
                    try:
                        slave_conn.close()
                    except Exception as e:
                        self.logger.debug(f"slave_conn.close(): {e}")

        return results

    def _foe_read_on_conn(self, conn, filename):
        """Read a file via FoE on an already-open pyads connection.

        Two-pass strategy (pyads discards data on short-read RuntimeError):
          1. Probe pass: chunked reads to determine total file size
             - Detects AMS router zero-fill (first chunk all zeros at exact buffer size)
          2. Exact pass: re-open and read with exact known size

        Args:
            conn: Open pyads.Connection (caller manages open/close)
            filename: Filename to read from slave

        Returns:
            Dict with {success, data, size} or {success: False, error, hint}
        """
        handle = None
        write_data = filename.encode("utf-8")
        try:
            # Pass 1: Open and probe for size
            handle_data = _read_write_raw(conn, ADS_IDX_GRP["ECAT_FOE_OPEN_R"], 0, 4, write_data)
            if not handle_data or len(handle_data) < 4:
                return {"success": False, "error": "FoE open returned no handle"}
            handle = struct.unpack("<I", handle_data[:4])[0]
            self.logger.debug(f"  FoE probe open '{filename}': handle=0x{handle:08X}")

            chunk_size = 4096
            total_size = 0
            first_chunk_zero = False

            while True:
                try:
                    chunk = _read_write_raw(
                        conn, ADS_IDX_GRP["ECAT_FOE_READ_DATA"], handle, chunk_size, b""
                    )
                    if (
                        total_size == 0
                        and len(chunk) == chunk_size
                        and chunk == b"\x00" * chunk_size
                    ):
                        first_chunk_zero = True
                        self.logger.debug(
                            f"  FoE '{filename}': first chunk all zeros — router zero-fill"
                        )
                        break
                    total_size += len(chunk)
                    if len(chunk) < chunk_size:
                        break
                except RuntimeError as short_e:
                    m = re.search(r"(\d+)\s+were\s+read", str(short_e))
                    if m:
                        total_size += int(m.group(1))
                    break
                except Exception:
                    break

            # Close probe handle
            try:
                _read_write_raw(conn, ADS_IDX_GRP["ECAT_FOE_CLOSE"], handle, 4, b"")
            except Exception as e:
                self.logger.debug(f"_read_write_raw call failed: {e}")
            handle = None
            self.logger.debug(f"  FoE '{filename}': probe pass done, total_size={total_size}")

            if first_chunk_zero:
                return {"success": False, "error": "zero-fill", "hint": "AMS router proxy"}

            if total_size == 0:
                return {"success": False, "error": "FoE file is empty or unreadable"}

            # Pass 2: Re-open and read with exact known size
            self.logger.debug(f"  FoE '{filename}': re-opening for exact read ({total_size} bytes)")
            handle_data = _read_write_raw(conn, ADS_IDX_GRP["ECAT_FOE_OPEN_R"], 0, 4, write_data)
            if not handle_data or len(handle_data) < 4:
                return {"success": False, "error": "FoE re-open failed"}
            handle = struct.unpack("<I", handle_data[:4])[0]
            self.logger.debug(f"  FoE re-open handle: 0x{handle:08X}")

            data = _read_write_raw(conn, ADS_IDX_GRP["ECAT_FOE_READ_DATA"], handle, total_size, b"")

            # Close
            try:
                _read_write_raw(conn, ADS_IDX_GRP["ECAT_FOE_CLOSE"], handle, 4, b"")
            except Exception as e:
                self.logger.debug(f"_read_write_raw call failed: {e}")
            handle = None

            self.logger.debug(f"  FoE '{filename}': exact read complete, {len(data)} bytes")
            return {"success": True, "data": data, "size": len(data)}

        except Exception as e:
            err_str = str(e)
            code = _extract_ads_error_code(err_str)
            self.logger.debug(f"  FoE '{filename}': error code={code}, {err_str}")
            hint = ""
            if code == 1796:
                hint = "access denied — needs Bootstrap state"
            elif code == 1793:
                hint = "service not supported"
            elif code == 1823:
                hint = "request aborted — needs Bootstrap or router proxy"
            elif _is_ads_timeout(err_str):
                hint = "timeout"
            return {"success": False, "error": _extract_ads_error(err_str), "hint": hint}
        finally:
            if handle is not None:
                try:
                    _read_write_raw(conn, ADS_IDX_GRP["ECAT_FOE_CLOSE"], handle, 4, b"")
                except Exception as e:
                    self.logger.debug(f"_read_write_raw call failed: {e}")

    def _foe_read_via_ads(self, port, filename):
        """Read a file from an EtherCAT slave via FoE handle-based protocol.

        Uses TwinCAT's handle-based FoE ADS abstraction (ig=0xF401-0xF404):
          1. Open:  ReadWrite(ig=0xF401, offset=0, write=filename) → 4-byte handle
          2. Read:  ReadWrite(ig=0xF404, offset=handle) → file data
          3. Close: ReadWrite(ig=0xF403, offset=handle)

        Args:
            port: ADS slave port number
            filename: Filename to read from slave

        Returns:
            Dict with success, data (bytes), size, or error info.
        """
        pyads = _get_pyads()
        slave_conn = None
        try:
            slave_conn = pyads.Connection(self.ams_netid, port)
            slave_conn.open()
            slave_conn.set_timeout(max(self.ads_timeout_ms, 5000))

            self.logger.display(f"  FoE read '{filename}' from port {port}...")
            result = self._foe_read_on_conn(slave_conn, filename)
            if result["success"]:
                self.logger.display(f"    Received {result['size']} bytes")
            return result

        except Exception as e:
            err_str = str(e)
            code = _extract_ads_error_code(err_str)
            hint = ""
            if code == 1796:
                hint = "access denied — slave needs Bootstrap state for FoE"
            elif code == 1793:
                hint = "service not supported — slave may not implement FoE"
            elif _is_ads_timeout(err_str):
                hint = "timeout — slave may not support FoE or needs Bootstrap mode"
            self.logger.debug(
                f"FoE read failed on port {port}: {e}" + (f" ({hint})" if hint else "")
            )
            return {"success": False, "error": err_str, "hint": hint}
        finally:
            if slave_conn:
                try:
                    slave_conn.close()
                except Exception as e:
                    self.logger.debug(f"slave_conn.close(): {e}")

    def _scan_foe_via_ads(self, slave_ports, save_dir=None):
        """Scan FoE (File over EtherCAT) support and probe common filenames on slaves.

        For each slave port:
        1. Probe FoE support by opening 'firmware.bin' for read
        2. If FoE accessible, iterate FOE_COMMON_FILENAMES to discover readable files
        3. Classify errors to distinguish real FoE from unsupported/denied
        4. If save_dir is set, downloaded files are saved to save_dir/port_XXXX/filename

        Args:
            slave_ports: List of ADS slave port numbers
            save_dir: Optional directory path to save downloaded files

        Returns:
            Dict mapping port -> {supported, state_hint, files: [{name, size, readable, path}]}
        """
        pyads = _get_pyads()
        results = {}

        for port in slave_ports:
            self.logger.display(f"  Probing FoE on port {port}...")
            slave_conn = None
            port_result = {"supported": False, "state_hint": "", "files": []}
            try:
                slave_conn = pyads.Connection(self.ams_netid, port)
                slave_conn.open()
                slave_conn.set_timeout(max(self.ads_timeout_ms, 2000))

                # Probe: open 'firmware.bin' + attempt read to distinguish
                # real FoE from AMS router proxy (router accepts opens for any
                # filename but reads abort with error 1823).
                probe_name = b"firmware.bin"
                try:
                    handle_data = _read_write_raw(
                        slave_conn, ADS_IDX_GRP["ECAT_FOE_OPEN_R"], 0, 4, probe_name
                    )
                    # Open succeeded — try a test read
                    port_result["supported"] = True
                    if handle_data and len(handle_data) >= 4:
                        handle = struct.unpack("<I", handle_data[:4])[0]
                        self.logger.debug(f"  FoE probe port {port}: handle=0x{handle:08X}")
                        try:
                            _read_write_raw(
                                slave_conn, ADS_IDX_GRP["ECAT_FOE_READ_DATA"], handle, 256, b""
                            )
                            port_result["state_hint"] = "accessible"
                        except Exception as read_e:
                            read_code = _extract_ads_error_code(str(read_e))
                            if read_code == 1823:
                                port_result["state_hint"] = (
                                    "open accepted, reads abort (1823) — "
                                    "needs Bootstrap or AMS router proxy"
                                )
                            elif read_code == 1796:
                                port_result["state_hint"] = "access denied — needs Bootstrap state"
                            else:
                                port_result["state_hint"] = (
                                    f"open OK, read error: {_extract_ads_error(str(read_e))}"
                                )
                        finally:
                            try:
                                _read_write_raw(
                                    slave_conn, ADS_IDX_GRP["ECAT_FOE_CLOSE"], handle, 4, b""
                                )
                            except Exception as e:
                                self.logger.debug(f"_read_write_raw call failed: {e}")
                except Exception as e:
                    err_str = str(e)
                    code = _extract_ads_error_code(err_str)
                    if code == 24:
                        self.logger.display(f"    Port {port}: not a real port (AMS error 24)")
                        results[port] = port_result
                        continue
                    elif code == 1793:
                        self.logger.display(f"    Port {port}: FoE not supported (error 1793)")
                        results[port] = port_result
                        continue
                    elif code == 1796:
                        port_result["supported"] = True
                        port_result["state_hint"] = "access denied — needs Bootstrap state"
                        self.logger.display(
                            f"    Port {port}: FoE supported (access denied — needs Bootstrap)"
                        )
                        results[port] = port_result
                        continue
                    elif _is_ads_timeout(err_str):
                        port_result["state_hint"] = "timeout"
                        self.logger.display(f"    Port {port}: FoE probe timeout")
                        results[port] = port_result
                        continue
                    else:
                        port_result["supported"] = True
                        port_result["state_hint"] = f"error: {_extract_ads_error(err_str)}"

                # Scan all filenames if FoE is supported (even if probe read
                # failed with 1823 — device may be selective about which files
                # are accessible, as seen with device-specific files like systrace).
                if port_result["supported"]:
                    slave_conn.set_timeout(max(self.ads_timeout_ms, 5000))
                    readable_count = 0
                    for fname in FOE_COMMON_FILENAMES:
                        read_result = self._foe_read_on_conn(slave_conn, fname)
                        if read_result["success"]:
                            self.logger.debug(
                                f"  FoE port {port}: '{fname}' readable, {read_result['size']} bytes"
                            )
                            file_entry = {
                                "name": fname,
                                "size": read_result["size"],
                                "readable": True,
                            }
                            # Save to disk if save_dir is set
                            if save_dir:
                                from oida.utils.common_types import safe_output_path

                                port_dir = os.path.join(save_dir, f"port_{port}")
                                os.makedirs(port_dir, exist_ok=True)
                                try:
                                    filepath = safe_output_path(fname, port_dir)
                                except ValueError:
                                    self.logger.debug(f"  FoE: skipped unsafe name: {fname}")
                                    continue
                                with open(filepath, "wb") as f:
                                    f.write(read_result["data"])
                                file_entry["path"] = filepath
                                self.logger.debug(f"  FoE saved: {filepath}")
                            port_result["files"].append(file_entry)
                            readable_count += 1
                        else:
                            self.logger.debug(
                                f"  FoE port {port}: '{fname}' — {read_result.get('error', 'failed')}"
                            )

                    if readable_count:
                        port_result["state_hint"] = "accessible"
                    self.logger.display(
                        f"    Port {port}: FoE supported, {readable_count} readable file(s)"
                    )

            except Exception as e:
                self.logger.debug(f"FoE scan failed on port {port}: {e}")
            finally:
                if slave_conn:
                    try:
                        slave_conn.close()
                    except Exception as e:
                        self.logger.debug(f"slave_conn.close(): {e}")

            results[port] = port_result

        return results

    def _foe_list_via_ads(self, port, patterns=None, save_dir=None):
        """Deep-probe FoE files on a single slave port.

        FoE has no directory listing. Tries all common filenames plus
        optional user-specified patterns. Uses _foe_read_on_conn for
        each file (handles zero-fill detection, proper two-pass read).

        If save_dir is set, downloaded files are saved to save_dir/filename.

        Args:
            port: ADS slave port number
            patterns: Optional list of additional filenames to try
            save_dir: Optional directory path to save downloaded files

        Returns:
            Dict with port, supported, files: [{name, size, error, path}]
        """
        pyads = _get_pyads()
        filenames = list(FOE_COMMON_FILENAMES)
        if patterns:
            for p in patterns:
                if p not in filenames:
                    filenames.append(p)

        result = {"port": port, "supported": False, "files": []}
        slave_conn = None
        try:
            slave_conn = pyads.Connection(self.ams_netid, port)
            slave_conn.open()
            slave_conn.set_timeout(max(self.ads_timeout_ms, 5000))

            for fname in filenames:
                read_result = self._foe_read_on_conn(slave_conn, fname)
                if read_result["success"]:
                    result["supported"] = True
                    self.logger.debug(
                        f"  FoE list port {port}: '{fname}' readable, {read_result['size']} bytes"
                    )
                    file_entry = {"name": fname, "size": read_result["size"], "error": None}
                    if save_dir:
                        from oida.utils.common_types import safe_output_path

                        os.makedirs(save_dir, exist_ok=True)
                        try:
                            filepath = safe_output_path(fname, save_dir)
                        except ValueError:
                            self.logger.debug(f"  FoE: skipped unsafe name: {fname}")
                            continue
                        with open(filepath, "wb") as f:
                            f.write(read_result["data"])
                        file_entry["path"] = filepath
                        self.logger.debug(f"  FoE saved: {filepath}")
                    result["files"].append(file_entry)
                elif read_result.get("error") == "zero-fill":
                    self.logger.debug(f"  FoE list port {port}: '{fname}' — zero-fill (skip)")
                    continue  # Router proxy — skip
                else:
                    # Classify error
                    hint = read_result.get("hint", "")
                    err = read_result.get("error", "")
                    code = _extract_ads_error_code(err)
                    self.logger.debug(
                        f"  FoE list port {port}: '{fname}' — error code={code}, {err}"
                    )
                    if code == 24:
                        result["error"] = "Invalid AMS port"
                        break
                    elif code == 1793 or hint == "service not supported":
                        result["error"] = "FoE not supported"
                        break
                    elif code == 1796 or "access denied" in hint:
                        result["supported"] = True
                        result["files"].append(
                            {
                                "name": fname,
                                "size": 0,
                                "error": "access denied (needs Bootstrap)",
                            }
                        )
                    # Other errors: file not found, continue probing

        except Exception as e:
            result["error"] = str(e)
            self.logger.debug(f"FoE list failed on port {port}: {e}")
        finally:
            if slave_conn:
                try:
                    slave_conn.close()
                except Exception as e:
                    self.logger.debug(f"slave_conn.close(): {e}")

        return result

    def _foe_write_via_ads(self, port, remote_name, data):
        """Write file data to an EtherCAT slave via FoE handle-based protocol.

        Uses TwinCAT's handle-based FoE ADS abstraction:
          1. Open:  ReadWrite(ig=0xF402, offset=0, write=filename) -> handle
          2. Write: ReadWrite(ig=0xF405, offset=handle, write=chunk) -> ack
          3. Close: ReadWrite(ig=0xF403, offset=handle)

        Args:
            port: ADS slave port number
            remote_name: Filename on the slave
            data: File content as bytes

        Returns:
            Dict with success, bytes_written, error, hint.
        """
        pyads = _get_pyads()
        slave_conn = None
        handle = None
        chunk_size = 512  # Standard EtherCAT mailbox size
        try:
            slave_conn = pyads.Connection(self.ams_netid, port)
            slave_conn.open()
            slave_conn.set_timeout(max(self.ads_timeout_ms, 5000))

            self.logger.display(
                f"  FoE write '{remote_name}' to port {port} ({len(data)} bytes)..."
            )

            # Step 1: Open file for writing
            handle_data = _read_write_raw(
                slave_conn, ADS_IDX_GRP["ECAT_FOE_OPEN_W"], 0, 4, remote_name.encode("utf-8")
            )
            if not handle_data or len(handle_data) < 4:
                return {
                    "success": False,
                    "bytes_written": 0,
                    "error": "FoE open returned no handle",
                }
            handle = struct.unpack("<I", handle_data[:4])[0]
            self.logger.debug(f"  FoE write handle: 0x{handle:08X}")

            # Step 2: Write data in chunks
            bytes_written = 0
            offset = 0
            total = len(data)
            while offset < total:
                chunk = data[offset : offset + chunk_size]
                try:
                    _read_write_raw(
                        slave_conn, ADS_IDX_GRP["ECAT_FOE_WRITE_DATA"], handle, 4, chunk
                    )
                except RuntimeError as e:
                    # A short-read on the ack ("N were read") is benign — the device
                    # may return fewer than the requested 4 bytes. Any other
                    # RuntimeError is a genuine write rejection: abort and fail.
                    if not re.search(r"were\s+read", str(e)):
                        return {
                            "success": False,
                            "bytes_written": bytes_written,
                            "error": f"FoE write chunk rejected at offset {offset}: {e}",
                        }
                    self.logger.debug(f"  FoE write ack short-read (benign): {e}")
                bytes_written += len(chunk)
                offset += len(chunk)
                if total > chunk_size:
                    self.logger.display(
                        f"    Progress: {bytes_written}/{total} bytes "
                        f"({100 * bytes_written // total}%)"
                    )

            self.logger.display(f"    Wrote {bytes_written} bytes")

            # Step 3: Close handle
            try:
                _read_write_raw(slave_conn, ADS_IDX_GRP["ECAT_FOE_CLOSE"], handle, 4, b"")
            except Exception as e:
                self.logger.debug(f"  FoE close warning: {e}")

            handle = None
            return {"success": True, "bytes_written": bytes_written, "error": None, "hint": None}

        except Exception as e:
            err_str = str(e)
            code = _extract_ads_error_code(err_str)
            hint = ""
            if code == 1796:
                hint = "access denied — slave needs Bootstrap state for FoE write"
            elif code == 1793:
                hint = "service not supported — slave may not implement FoE"
            elif _is_ads_timeout(err_str):
                hint = "timeout — slave may not support FoE or needs Bootstrap mode"
            self.logger.debug(
                f"FoE write failed on port {port}: {e}" + (f" ({hint})" if hint else "")
            )
            return {"success": False, "bytes_written": 0, "error": err_str, "hint": hint}
        finally:
            if handle is not None and slave_conn:
                try:
                    _read_write_raw(slave_conn, ADS_IDX_GRP["ECAT_FOE_CLOSE"], handle, 4, b"")
                except Exception as e:
                    self.logger.debug(f"_read_write_raw call failed: {e}")
            if slave_conn:
                try:
                    slave_conn.close()
                except Exception as e:
                    self.logger.debug(f"slave_conn.close(): {e}")

    def _scan_soe_via_ads(self, slave_ports):
        """Scan SoE (Servo-over-EtherCAT) IDNs on slaves via ADS bridge.

        Reads standard SoE IDNs from each slave port using ig=0xF420.

        Args:
            slave_ports: List of ADS slave port numbers

        Returns:
            Dict mapping port to {idn: {name, value_hex, ...}, ...}
        """
        pyads = _get_pyads()
        results = {}

        for port in slave_ports:
            self.logger.display(f"  Scanning SoE IDNs on port {port}...")
            slave_conn = None
            port_idns = {}
            try:
                slave_conn = pyads.Connection(self.ams_netid, port)
                slave_conn.open()
                slave_conn.set_timeout(self.ads_timeout_ms)

                # Probe: read IDN 1 element 7 with 256B buffer.
                # Real SoE returns short-read or non-zero; AMS router returns 256 zero bytes.
                probe_offset = encode_soe_offset(1, element=7)
                try:
                    probe = _read_raw(slave_conn, ADS_IDX_GRP["ECAT_SOE_READ"], probe_offset, 256)
                    if len(probe) == 256 and probe == b"\x00" * 256:
                        self.logger.display(
                            f"    Port {port}: SoE not supported (AMS router zero-fill detected)"
                        )
                        continue
                except RuntimeError as e:
                    self.logger.debug(
                        f"Failed to get probe: {e}"
                    )  # Short-read = real SoE service, proceed
                except Exception as e:
                    err_str = str(e)
                    if _is_ads_timeout(err_str):
                        self.logger.display(f"    Port {port}: SoE timeout")
                    elif "1795" in err_str or "1793" in err_str:
                        self.logger.display(
                            f"    Port {port}: SoE not supported (ADS error {_extract_ads_error(err_str)})"
                        )
                    else:
                        self.logger.display(f"    Port {port}: SoE probe failed ({e})")
                    continue

                progress = ProgressTracker(
                    len(SOE_STANDARD_IDNS),
                    threshold=1.0,
                    interval=0.5,
                    logger=self.logger,
                    show=True,
                )

                for idn, idn_name in sorted(SOE_STANDARD_IDNS.items()):
                    progress.update()
                    idn_result = {"idn": idn, "standard_name": idn_name}

                    # Read element 7 (Value)
                    offset_val = encode_soe_offset(idn, element=7)
                    val_data = self._soe_read_with_retry(slave_conn, offset_val)
                    if val_data is not None:
                        idn_result["value_hex"] = val_data.hex()
                        idn_result["value_size"] = len(val_data)
                        if len(val_data) <= 4:
                            idn_result["value"] = int.from_bytes(val_data, "little")
                    else:
                        # IDN not supported on this slave
                        continue

                    # Read element 2 (Name) — optional
                    offset_name = encode_soe_offset(idn, element=2)
                    name_data = self._soe_read_with_retry(slave_conn, offset_name)
                    if name_data is not None:
                        idn_result["device_name"] = name_data.rstrip(b"\x00").decode(
                            "utf-8", errors="replace"
                        )

                    port_idns[idn] = idn_result

                progress.finish()

                self.logger.display(f"    Found {len(port_idns)} IDNs")

            except Exception as e:
                self.logger.debug(f"SoE scan failed on port {port}: {e}")
            finally:
                if slave_conn:
                    try:
                        slave_conn.close()
                    except Exception as e:
                        self.logger.debug(f"slave_conn.close(): {e}")

            results[port] = port_idns

        return results

    def _scan_fsoe_via_ads(self, slave_ports):
        """Scan FSoE (Functional Safety over EtherCAT) objects on slaves via CoE SDO.

        Reads FSoE-specific CoE objects (0xF1xx, 0xF9xx range) from each slave:
        1. Probe 0xF980:1 (FSoE Connection Count) to detect FSoE support
        2. If supported, read all FSOE_COE_OBJECTS entries
        3. Decode values according to type (uint8/16/32, string, octets)

        Args:
            slave_ports: List of ADS slave port numbers

        Returns:
            Dict mapping port -> {fsoe_supported, connection_count, objects: [{index, sub, name, type, value, raw}]}
        """
        pyads = _get_pyads()
        results = {}

        for port in slave_ports:
            self.logger.display(f"  Probing FSoE on port {port}...")
            slave_conn = None
            port_result = {
                "fsoe_supported": False,
                "connection_count": None,
                "objects": [],
                "error": None,
            }
            try:
                slave_conn = pyads.Connection(self.ams_netid, port)
                slave_conn.open()
                slave_conn.set_timeout(max(self.ads_timeout_ms, 2000))

                # Probe: read 0xF980:1 (FSoE Connection Count)
                probe_offset = (0xF980 << 16) | 1
                try:
                    probe_data = _read_raw(slave_conn, ADS_IDX_GRP["COE_SDO"], probe_offset, 2)
                    if probe_data and len(probe_data) == 2 and probe_data != b"\x00\x00":
                        conn_count = struct.unpack("<H", probe_data)[0]
                        port_result["fsoe_supported"] = True
                        port_result["connection_count"] = conn_count
                        self.logger.display(
                            f"    Port {port}: FSoE supported ({conn_count} connection(s))"
                        )
                    elif probe_data == b"\x00\x00":
                        # Zero could be valid (0 connections) or router zero-fill.
                        # Try subindex 0 to distinguish.
                        probe0 = _read_raw(
                            slave_conn, ADS_IDX_GRP["COE_SDO"], (0xF980 << 16) | 0, 1
                        )
                        if probe0 and probe0 != b"\x00":
                            port_result["fsoe_supported"] = True
                            port_result["connection_count"] = 0
                            self.logger.display(f"    Port {port}: FSoE supported (0 connections)")
                        else:
                            self.logger.display(f"    Port {port}: FSoE not detected (zero-fill)")
                            results[port] = port_result
                            continue
                except RuntimeError:
                    # Short-read = real data, FSoE supported
                    port_result["fsoe_supported"] = True
                    port_result["connection_count"] = -1
                    self.logger.display(f"    Port {port}: FSoE supported (short-read on probe)")
                except Exception as e:
                    err_str = str(e)
                    code = _extract_ads_error_code(err_str)
                    if code == 24:
                        self.logger.display(f"    Port {port}: not a real port (AMS error 24)")
                        results[port] = port_result
                        continue
                    elif code in (1793, 1823):
                        self.logger.display(f"    Port {port}: FSoE not supported")
                        results[port] = port_result
                        continue
                    elif code == 1796:
                        port_result["fsoe_supported"] = True
                        port_result["error"] = "access denied"
                        self.logger.display(f"    Port {port}: FSoE object exists (access denied)")
                    elif _is_ads_timeout(err_str):
                        self.logger.display(f"    Port {port}: FSoE probe timeout")
                        results[port] = port_result
                        continue
                    else:
                        self.logger.debug(f"    Port {port}: FSoE probe error: {e}")
                        results[port] = port_result
                        continue

                # Read all FSoE objects
                if port_result["fsoe_supported"]:
                    slave_conn.set_timeout(max(self.ads_timeout_ms, 3000))

                    def _decode(dtype, data, obj_entry):
                        """Decode raw CoE bytes into obj_entry['value'] by dtype."""
                        obj_entry["raw"] = data.hex()
                        if dtype == "uint8" and len(data) >= 1:
                            obj_entry["value"] = data[0]
                        elif dtype == "uint16" and len(data) >= 2:
                            obj_entry["value"] = struct.unpack("<H", data[:2])[0]
                        elif dtype == "uint32" and len(data) >= 4:
                            obj_entry["value"] = struct.unpack("<I", data[:4])[0]
                        elif dtype == "string":
                            obj_entry["value"] = data.rstrip(b"\x00").decode(
                                "utf-8", errors="replace"
                            )
                        elif dtype == "octets":
                            obj_entry["value"] = data.hex()

                    for idx, sub, name, dtype, read_sz in FSOE_COE_OBJECTS + FSOE_PARAM_OBJECTS:
                        offset = (idx << 16) | sub
                        obj_entry = {
                            "index": idx,
                            "subindex": sub,
                            "name": name,
                            "type": dtype,
                        }
                        try:
                            data = _read_raw(slave_conn, ADS_IDX_GRP["COE_SDO"], offset, read_sz)
                            if data is None or (
                                len(data) == read_sz and data == b"\x00" * read_sz and read_sz >= 8
                            ):
                                # Likely router zero-fill for larger buffers
                                self.logger.debug(
                                    f"  FSoE port {port}: 0x{idx:04X}:{sub} — zero-fill ({read_sz}B), skip"
                                )
                                continue

                            _decode(dtype, data, obj_entry)

                            port_result["objects"].append(obj_entry)

                        except RuntimeError as short_e:
                            # Short-read — re-read with actual size
                            m = re.search(r"(\d+)\s+were\s+read", str(short_e))
                            if m:
                                actual = int(m.group(1))
                                self.logger.debug(
                                    f"  FSoE port {port}: 0x{idx:04X}:{sub} short-read "
                                    f"({actual}/{read_sz}), re-reading"
                                )
                                try:
                                    data = _read_raw(
                                        slave_conn, ADS_IDX_GRP["COE_SDO"], offset, actual
                                    )
                                    _decode(dtype, data, obj_entry)
                                    port_result["objects"].append(obj_entry)
                                except Exception:
                                    obj_entry["error"] = f"short-read ({actual}/{read_sz})"
                                    port_result["objects"].append(obj_entry)
                        except Exception as e:
                            code = _extract_ads_error_code(str(e))
                            if code in (24, 1793, 1823):
                                self.logger.debug(
                                    f"  FSoE port {port}: 0x{idx:04X}:{sub} — "
                                    f"not supported (error {code})"
                                )
                                continue
                            elif code == 1796:
                                self.logger.debug(
                                    f"  FSoE port {port}: 0x{idx:04X}:{sub} — access denied"
                                )
                                obj_entry["error"] = "access denied"
                                port_result["objects"].append(obj_entry)
                            else:
                                self.logger.debug(
                                    f"  FSoE port {port}: 0x{idx:04X}:{sub} — error: {e}"
                                )

                    self.logger.display(f"    Read {len(port_result['objects'])} FSoE object(s)")

            except Exception as e:
                self.logger.debug(f"FSoE scan failed on port {port}: {e}")
            finally:
                if slave_conn:
                    try:
                        slave_conn.close()
                    except Exception as e:
                        self.logger.debug(f"slave_conn.close(): {e}")

            results[port] = port_result

        return results

    def _read_soe_idn_via_ads(self, port, idn, drive=0):
        """Read all SoE elements for a single IDN via ADS bridge.

        Args:
            port: ADS slave port number
            idn: SoE IDN number
            drive: Drive number (default 0)

        Returns:
            Dict with all readable SoE elements.
        """
        pyads = _get_pyads()
        slave_conn = None
        result = {"idn": idn, "drive": drive, "elements": {}}
        try:
            slave_conn = pyads.Connection(self.ams_netid, port)
            slave_conn.open()
            slave_conn.set_timeout(self.ads_timeout_ms)

            # Probe for AMS router zero-fill
            probe_offset = encode_soe_offset(idn, element=7, drive=drive)
            try:
                probe = _read_raw(slave_conn, ADS_IDX_GRP["ECAT_SOE_READ"], probe_offset, 256)
                if len(probe) == 256 and probe == b"\x00" * 256:
                    result["error"] = "SoE not supported (AMS router zero-fill)"
                    return result
            except RuntimeError as e:
                self.logger.debug(f"Failed to get probe: {e}")  # Short-read = real SoE
            except Exception as e:
                result["error"] = str(e)
                return result

            for elem_id, elem_name in sorted(SOE_ELEMENTS.items()):
                offset = encode_soe_offset(idn, element=elem_id, drive=drive)
                data = self._soe_read_with_retry(slave_conn, offset)
                if data is not None:
                    entry = {"name": elem_name, "data_hex": data.hex(), "size": len(data)}
                    if elem_id == 2:
                        # Name element — decode as string
                        entry["text"] = data.rstrip(b"\x00").decode("utf-8", errors="replace")
                    elif elem_id == 4:
                        # Unit element — decode as string
                        entry["text"] = data.rstrip(b"\x00").decode("utf-8", errors="replace")
                    elif len(data) <= 4:
                        entry["value"] = int.from_bytes(data, "little")
                    result["elements"][elem_id] = entry

        except Exception as e:
            result["error"] = str(e)
            self.logger.debug(f"SoE IDN {idn} read failed on port {port}: {e}")
        finally:
            if slave_conn:
                try:
                    slave_conn.close()
                except Exception as e:
                    self.logger.debug(f"slave_conn.close(): {e}")

        return result

    @staticmethod
    def _soe_read_with_retry(conn, offset):
        """Read SoE data via ig=0xF420 with short-read retry.

        Returns raw bytes or None if the IDN doesn't exist.
        Filters out AMS router zero-fill (256 zero bytes = not real data).
        """
        ig = ADS_IDX_GRP["ECAT_SOE_READ"]
        try:
            data = _read_raw(conn, ig, offset, 256)
            # Filter router zeros: 256 bytes all-zero is AMS router, not real SoE
            if len(data) == 256 and data == b"\x00" * 256:
                return None
            return data
        except RuntimeError as e:
            m = re.search(r"(\d+)\s+were\s+read", str(e))
            if m:
                actual = int(m.group(1))
                if actual > 0:
                    return _read_raw(conn, ig, offset, actual)
            return None
        except Exception as e:
            logger.debug(f"ECAT SoE read via ADS bridge failed: {e}")
            return None

    def _fuzz_coe_via_ads(self, slave_ports, iterations=10, scan_ranges=None, force_write=False):
        """Fuzz writable CoE SDO objects on EtherCAT slaves via ADS bridge.

        Reuses _scan_coe_via_ads() to discover objects, then generates mutations
        using the central fuzz() utility.

        Args:
            slave_ports: List of ADS slave port numbers
            iterations: Number of fuzz iterations per object
            scan_ranges: Override COE_SCAN_RANGES for writable target discovery
            force_write: If True, fuzz all readable objects regardless of access test

        Returns:
            Dict mapping port to list of fuzz result dicts.
        """
        import time
        from ...utils.fuzzer import fuzz

        pyads = _get_pyads()
        results = {}

        # Discover objects — skip access test when force-writing (just scan for readable objects)
        if force_write:
            coe_scan = self._scan_coe_via_ads(
                slave_ports, test_access=False, scan_ranges=scan_ranges
            )
        else:
            coe_scan = self._scan_coe_via_ads(
                slave_ports, test_access=True, scan_ranges=scan_ranges
            )

        for port in slave_ports:
            self.logger.display(f"  Fuzzing CoE on port {port}...")
            slave_conn = None
            port_results = []

            # Filter targets: force_write takes all readable objects, otherwise only RW
            port_objects = coe_scan.get(port, [])
            targets = []
            for obj in port_objects:
                if not obj.get("data"):
                    continue
                if not force_write and obj.get("access") != "RW":
                    continue
                idx = int(obj["index"], 16)
                sub = obj["subindex"]
                data = bytes.fromhex(obj["data"])
                targets.append((idx, sub, data))

            if not targets:
                label = "readable" if force_write else "writable"
                self.logger.display(f"    No {label} objects found on port {port}")
                results[port] = port_results
                continue

            if force_write:
                self.logger.display(
                    f"    Force-writing {len(targets)} objects (access test skipped)"
                )
            else:
                self.logger.display(f"    Found {len(targets)} writable objects")
            for idx, sub, data in targets:
                self.logger.debug(
                    f"    target 0x{idx:04X}:{sub} size={len(data)} original={data.hex()}"
                )

            fuzz_total = len(targets) * iterations
            fuzz_progress = ProgressTracker(
                fuzz_total,
                threshold=1.0,
                interval=0.5,
                logger=self.logger,
                show=True,
            )

            try:
                slave_conn = pyads.Connection(self.ams_netid, port)
                slave_conn.open()
                slave_conn.set_timeout(self.ads_timeout_ms)

                for idx, sub, original in targets:
                    name = get_coe_object_name(idx, sub)
                    accepted = 0
                    rejected = 0
                    crashes = 0
                    mutation_num = 0

                    self.logger.debug(
                        f"Fuzzing 0x{idx:04X}:{sub} ({name}): {iterations} iterations, "
                        f"original={original.hex()} ({len(original)}B)"
                    )

                    for payload, mutation_desc in fuzz(
                        original, count=iterations, max_len=len(original)
                    ):
                        mutation_num += 1
                        fuzz_progress.update()
                        try:
                            ok, err = _write_coe_sdo(slave_conn, idx, sub, payload)
                            if ok:
                                accepted += 1
                                self.logger.debug(
                                    f"  #{mutation_num} ACCEPTED {mutation_desc}: {payload.hex()}"
                                )
                            else:
                                rejected += 1
                                self.logger.debug(
                                    f"  #{mutation_num} REJECTED {mutation_desc}: "
                                    f"{payload.hex()} -> {err}"
                                )
                        except Exception as e:
                            crashes += 1
                            self.logger.debug(
                                f"  #{mutation_num} CRASH {mutation_desc}: {payload.hex()} -> {e}"
                            )
                        time.sleep(ADS_FUZZ_DELAY)

                    # Restore original value
                    ok, err = _write_coe_sdo(slave_conn, idx, sub, original)
                    if ok:
                        self.logger.debug(f"Restored 0x{idx:04X}:{sub} to {original.hex()}")
                    else:
                        self.logger.warning(
                            f"Failed to restore 0x{idx:04X}:{sub} on port {port}: {err}"
                        )

                    status = "+" if crashes == 0 else "!"
                    self.logger.display(
                        f"    [{status}] 0x{idx:04X}:{sub} ({name}): "
                        f"{accepted + rejected} tested, "
                        f"{accepted} accepted, {rejected} rejected, {crashes} crashes"
                    )

                    port_results.append(
                        {
                            "index": f"0x{idx:04X}",
                            "subindex": sub,
                            "name": name,
                            "original_size": len(original),
                            "iterations": accepted + rejected + crashes,
                            "accepted": accepted,
                            "rejected": rejected,
                            "crashes": crashes,
                        }
                    )

                fuzz_progress.finish()

            except Exception as e:
                self.logger.debug(f"CoE fuzz port {port} failed: {e}")
            finally:
                if slave_conn:
                    try:
                        slave_conn.close()
                    except Exception as e:
                        self.logger.debug(f"slave_conn.close(): {e}")

            results[port] = port_results
            self.logger.debug(f"Port {port}: fuzz complete, {len(port_results)} objects tested")

        return results
