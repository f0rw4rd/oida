#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ADS NXC-style Connection (Layer 2) -- Auto-execute on instantiation.

Provides the ``ads`` callable class that inherits from NetworkConnection
and triggers scanning automatically via proto_flow() in __init__.
Used by the CLI and framework integrations.
"""

import ctypes
import fnmatch
import os
import struct
import tempfile

from ...connection import NetworkConnection
from ...utils import ProgressTracker
from ...utils.export_utils import export_data

# Shared CoE definitions
from ..ethercat.coe import (
    get_al_state_name,
    encode_sdo_offset,
    get_coe_object_name,
)
from ..ethercat.constants import lookup_vendor
from ..ethercat.soe import SOE_STANDARD_IDNS

# ADS protocol constants
from .constants import (
    ADS_FUZZ_SYMBOL_DELAY,
    ADS_IDX_GRP,
    ADS_PORT_MAP,
    ADS_STATE_MAP,
    ADS_UDP_TIMEOUT,
    AMS_SERVICE_PORTS,
)

# Shared helpers
from .helpers import (
    _pyads,
    _get_pyads,
    _get_memory_areas,
    _read_raw,
    _read_coe_sdo,
    _write_raw,
    _probe_netid,
    _capture_pyads_stderr,
)

# Scanner class (Layer 1) -- used to create scanner instances in proto_flow
from .scanner import ADSScanner

import logging

logger = logging.getLogger(__name__)


class ads(NetworkConnection):
    """NXC-style ADS scanner (callable on instantiation)"""

    def __init__(self, args, db, host):
        self.protocol_name = "ADS"
        self.default_port = 48898
        self._scan_results = None
        self._connection = None
        super().__init__(args, db, host)

    def proto_flow(self):
        """Main ADS scanning workflow"""

        # Refuse dangerous ops without --confirm (state-change, writes, fuzz).
        from .proto_args import validate_args

        validate_args(self.args)

        # Build scanner args
        args_dict = self._convert_args_to_dict()
        self.scanner = ADSScanner(args_dict)

        # Capture pyads C library stderr (Info/Error/Warning lines)
        # and route through oida debug logger instead.
        with _capture_pyads_stderr(self.logger):
            # Connect
            self.create_conn_obj()
            if not self.conn:
                self.logger.fail(f"Failed to connect to {self.host}")
                self.results["success"] = False
                self.results["error"] = "Connection failed"
                return

            # Skip device-info probe for EtherCAT/CoE operations — they
            # open their own connections to specific slave ports.
            _ecat_op = any(
                [
                    getattr(self.args, "scan_ethercat", False),
                    getattr(self.args, "scan_coe", False),
                    getattr(self.args, "scan_coe_access", False),
                    getattr(self.args, "read_coe", None),
                    getattr(self.args, "write_coe", None),
                    getattr(self.args, "eeprom_dump", False),
                    getattr(self.args, "fuzz_coe", False),
                    getattr(self.args, "esc_registers", False),
                    getattr(self.args, "foe_read", None),
                    getattr(self.args, "scan_foe", False),
                    getattr(self.args, "foe_list", None),
                    getattr(self.args, "foe_write", None),
                    getattr(self.args, "foe_delete", None),
                    getattr(self.args, "scan_soe", False),
                    getattr(self.args, "read_soe", None),
                    getattr(self.args, "scan_fsoe", False),
                ]
            )
            if not _ecat_op:
                self.enum_host_info()
                self.print_host_info()

            # Handle operation modes
            self._execute_operations()

    def create_conn_obj(self):
        """Create ADS connection"""
        self.logger.debug(f"Connecting to {self.ip}:{self.args.port}")
        self.conn = self.scanner.connect()
        self._connection = self.conn
        if self.conn:
            self.logger.success("Connected to ADS device")
        else:
            self.logger.fail(f"Connection failed to {self.ip}:{self.args.port}")

    def enum_host_info(self):
        """Enumerate device information.

        Tries ``read_device_info()`` with a short timeout.  On failure
        (EtherCAT subsystems, non-PLC endpoints) the result is left
        empty — the probe runs lazily in ``_execute_operations`` only
        when no explicit operation was requested.
        """
        if not self.conn:
            return

        self.conn.set_timeout(self.scanner.ads_timeout_ms)
        try:
            dev_name, dev_version = self.conn.read_device_info()
            self.results["data"]["device_info"] = {
                "name": dev_name,
                "version": f"{dev_version.version}.{dev_version.revision}.{dev_version.build}",
            }

            ads_state, device_state = self.conn.read_state()
            self.results["data"]["state"] = {
                "ads_state": ads_state,
                "ads_state_name": ADS_STATE_MAP.get(ads_state, "UNKNOWN"),
                "device_state": device_state,
            }
        except Exception as e:
            self.logger.debug(f"read_device_info failed: {e}")

    def print_host_info(self):
        """Display device information"""
        if hasattr(self.args, "quiet") and self.args.quiet:
            return

        device_info = self.results["data"].get("device_info", {})
        state_info = self.results["data"].get("state", {})

        if device_info.get("name"):
            self.logger.display(
                f"Device: {device_info['name']} v{device_info.get('version', 'Unknown')}"
            )
        if state_info.get("ads_state_name"):
            self.logger.display(f"State: {state_info['ads_state_name']}")

    def _execute_operations(self):
        """Execute operations based on CLI flags"""
        if not self.conn:
            return

        # Warn if --coe-range is specified without a CoE operation
        if getattr(self.args, "coe_range", None) and not any(
            [
                getattr(self.args, "scan_coe", False),
                getattr(self.args, "scan_coe_access", False),
                getattr(self.args, "fuzz_coe", False),
            ]
        ):
            self.logger.warning(
                "--coe-range has no effect without --scan-coe, --scan-coe-access, or --fuzz-coe"
            )

        # --device-info (already done in enum)

        # --state (show detailed state)
        if getattr(self.args, "state", False):
            self._show_state()

        # --set-state
        if getattr(self.args, "set_state", None):
            self._set_state(self.args.set_state)

        # --list-symbols
        if getattr(self.args, "list_symbols", False):
            self._list_symbols()

        # --enumerate-symbols
        if getattr(self.args, "enumerate_symbols", False):
            self._enumerate_symbols()

        # --read-symbol
        if getattr(self.args, "read_symbol", None):
            self._read_symbol(self.args.read_symbol)

        # --write-symbol
        if getattr(self.args, "write_symbol", None):
            self._write_symbol(self.args.write_symbol)

        # --memory-read
        if getattr(self.args, "memory_read", None):
            self._memory_read(self.args.memory_read)

        # --memory-write
        if getattr(self.args, "memory_write", None):
            self._memory_write(self.args.memory_write)

        # --test-memory
        if getattr(self.args, "test_memory", False):
            self._test_memory()

        # --scan-ports / --scan-ports-extended
        if getattr(self.args, "scan_ports", False) or getattr(
            self.args, "scan_ports_extended", False
        ):
            extended = getattr(self.args, "scan_ports_extended", False)
            self._scan_ports(extended=extended)

        # --scan-routes
        if getattr(self.args, "scan_routes", False):
            self._scan_routes_nxc()

        # --target-desc
        if getattr(self.args, "target_desc", False):
            self._target_desc()

        # --check-secure
        if getattr(self.args, "check_secure", False):
            self._check_secure()

        # --udp-discovery
        if getattr(self.args, "udp_discovery", False):
            self._udp_discovery_nxc()

        # --license-info
        if getattr(self.args, "license_info", False):
            self._license_info_nxc()

        # --io-devices
        if getattr(self.args, "io_devices", False):
            self._io_devices_nxc()

        # --list-files
        if getattr(self.args, "list_files", None):
            self._list_files_nxc(self.args.list_files)

        # --read-file
        if getattr(self.args, "read_file", None):
            self._read_file_nxc(self.args.read_file)

        # --task-info
        if getattr(self.args, "task_info", False):
            self._task_info_nxc()

        # --read-registry
        if getattr(self.args, "read_registry", None):
            self._read_registry_nxc(self.args.read_registry)

        # --download-program
        if getattr(self.args, "download_program", False):
            self._download_program_nxc()

        # --scan-ethercat
        if getattr(self.args, "scan_ethercat", False):
            self._scan_ethercat_nxc()

        # --scan-coe
        if getattr(self.args, "scan_coe", False):
            self._scan_coe_nxc()

        # --read-coe
        if getattr(self.args, "read_coe", None):
            self._read_coe_nxc(self.args.read_coe)

        # --write-coe (requires --confirm)
        if getattr(self.args, "write_coe", None):
            if not getattr(self.args, "confirm", False):
                self.logger.fail("--write-coe requires --confirm (writes to device)")
            else:
                self._write_coe_nxc(self.args.write_coe)

        # --scan-coe-access (requires --confirm)
        if getattr(self.args, "scan_coe_access", False):
            self._scan_coe_access_nxc()

        # --eeprom-dump
        if getattr(self.args, "eeprom_dump", False):
            self._eeprom_dump_nxc()

        # --esc-registers
        if getattr(self.args, "esc_registers", False):
            self._esc_registers_nxc()

        # --foe-read
        if getattr(self.args, "foe_read", None):
            self._foe_read_nxc(self.args.foe_read)

        # --scan-foe
        if getattr(self.args, "scan_foe", False):
            self._scan_foe_nxc()

        # --foe-list
        if getattr(self.args, "foe_list", None):
            self._foe_list_nxc(self.args.foe_list)

        # --foe-write (requires --confirm)
        if getattr(self.args, "foe_write", None):
            if not getattr(self.args, "confirm", False):
                self.logger.fail("--foe-write requires --confirm (writes to device)")
            else:
                self._foe_write_nxc(self.args.foe_write)

        # --foe-delete (requires --confirm)
        if getattr(self.args, "foe_delete", None):
            if not getattr(self.args, "confirm", False):
                self.logger.fail("--foe-delete requires --confirm (deletes file on device)")
            else:
                self._foe_delete_nxc(self.args.foe_delete)

        # --scan-soe
        if getattr(self.args, "scan_soe", False):
            self._scan_soe_nxc()

        # --read-soe
        if getattr(self.args, "read_soe", None):
            self._read_soe_nxc(self.args.read_soe)

        # --scan-fsoe
        if getattr(self.args, "scan_fsoe", False):
            self._scan_fsoe_nxc()

        # --fuzz-coe (requires --confirm)
        if getattr(self.args, "fuzz_coe", False):
            self._fuzz_coe_nxc()

        # --add-route (requires --confirm)
        if getattr(self.args, "add_route", None):
            if not getattr(self.args, "confirm", False):
                self.logger.fail("--add-route requires --confirm (modifies target routing table)")
            else:
                self._add_route_nxc(self.args.add_route)

        # --fuzz
        if getattr(self.args, "fuzz", None):
            self._handle_fuzz()

        # --test-write (requires --confirm — writes values back to device)
        if getattr(self.args, "test_write", False):
            if not getattr(self.args, "confirm", False):
                self.logger.fail("--test-write requires --confirm (writes to device symbols)")
            else:
                self._test_write_access()

        # --watch (blocking — runs until Ctrl+C)
        if getattr(self.args, "watch", None):
            self._watch_symbol_nxc(self.args.watch)

        # Default: basic info only (device info + state already shown by enum_host_info)
        if not any(
            [
                getattr(self.args, "device_info", False),
                getattr(self.args, "state", False),
                getattr(self.args, "set_state", None),
                getattr(self.args, "list_symbols", False),
                getattr(self.args, "enumerate_symbols", False),
                getattr(self.args, "read_symbol", None),
                getattr(self.args, "write_symbol", None),
                getattr(self.args, "memory_read", None),
                getattr(self.args, "memory_write", None),
                getattr(self.args, "test_memory", False),
                getattr(self.args, "scan_ports", False),
                getattr(self.args, "scan_ports_extended", False),
                getattr(self.args, "scan_routes", False),
                getattr(self.args, "target_desc", False),
                getattr(self.args, "check_secure", False),
                getattr(self.args, "udp_discovery", False),
                getattr(self.args, "license_info", False),
                getattr(self.args, "io_devices", False),
                getattr(self.args, "list_files", None),
                getattr(self.args, "read_file", None),
                getattr(self.args, "read_registry", None),
                getattr(self.args, "download_program", False),
                getattr(self.args, "scan_ethercat", False),
                getattr(self.args, "scan_coe", False),
                getattr(self.args, "scan_coe_access", False),
                getattr(self.args, "read_coe", None),
                getattr(self.args, "write_coe", None),
                getattr(self.args, "eeprom_dump", False),
                getattr(self.args, "fuzz_coe", False),
                getattr(self.args, "esc_registers", False),
                getattr(self.args, "foe_read", None),
                getattr(self.args, "scan_foe", False),
                getattr(self.args, "foe_list", None),
                getattr(self.args, "foe_write", None),
                getattr(self.args, "foe_delete", None),
                getattr(self.args, "scan_soe", False),
                getattr(self.args, "read_soe", None),
                getattr(self.args, "scan_fsoe", False),
                getattr(self.args, "add_route", None),
                getattr(self.args, "fuzz", None),
                getattr(self.args, "test_write", False),
                getattr(self.args, "task_info", False),
                getattr(self.args, "watch", None),
            ]
        ):
            # No explicit operation requested — show enriched default summary
            self._default_summary()

    def _default_summary(self):
        """Show enriched summary when no explicit operation is requested."""
        device_info = self.results["data"].get("device_info", {})

        if not device_info.get("name"):
            # read_device_info failed — run full probe to classify endpoint
            pyads = _get_pyads()
            probe = _probe_netid(
                pyads,
                self.scanner.ams_netid,
                self.scanner._get_ads_port(),
                timeout_ms=self.scanner.ads_timeout_ms,
            )
            if probe["active"]:
                self.logger.display(
                    f"Endpoint: {self.scanner.ams_netid} ({probe['type']}: {probe['detail']})"
                )
            else:
                self.logger.fail(
                    f"No response from {self.scanner.ams_netid} on port "
                    f"{self.scanner._get_ads_port()} "
                    f"— Net ID may not exist. Try -r to discover active Net IDs."
                )
                return

        # --- UDP discovery (hostname, TwinCAT version, OS) ---
        try:
            udp_result = self.scanner._udp_discovery(timeout=ADS_UDP_TIMEOUT, quiet=True)
            if udp_result.get("devices"):
                dev = udp_result["devices"][0]
                if dev.get("hostname"):
                    self.logger.display(f"Hostname: {dev['hostname']}")
                if dev.get("tc_version"):
                    self.logger.display(f"TwinCAT: {dev['tc_version']}")
                if dev.get("os_version"):
                    self.logger.display(f"OS: {dev['os_version']}")
                if dev.get("fingerprint"):
                    self.logger.display(f"Fingerprint: {dev['fingerprint']}")
        except Exception as e:
            self.logger.debug(f"UDP discovery failed: {e}")

        # --- Symbol count (ig=0xF00C on current port) ---
        try:
            info_data = _read_raw(self.conn, ADS_IDX_GRP["SYM_UPLOAD_INFO"], 0, 24)
            if info_data and len(info_data) >= 12:
                sym_count = struct.unpack("<I", info_data[0:4])[0]
                sym_size = struct.unpack("<I", info_data[4:8])[0]
                self.logger.display(f"Symbols: {sym_count} ({sym_size} bytes)")
        except Exception as e:
            self.logger.debug(f"Symbol count probe failed: {e}")

        # --- Memory area sizes ---
        mem_areas = [
            ("MEM_SIZE_M", "%M (marker)"),
            ("IO_SIZE_I", "%I (input)"),
            ("IO_SIZE_Q", "%Q (output)"),
            ("MEM_SIZE_RB", "Retain"),
            ("MEM_SIZE_DB", "Data"),
        ]
        mem_lines = []
        for ig_key, label in mem_areas:
            try:
                data = _read_raw(self.conn, ADS_IDX_GRP[ig_key], 0, 4)
                if data and len(data) >= 4:
                    size = struct.unpack("<I", data)[0]
                    if size > 0:
                        mem_lines.append(f"{label}={size}")
            except Exception as e:
                self.logger.debug(f"ADS memory area size read failed for {ig_key}: {e}")
        if mem_lines:
            self.logger.display(f"Memory: {', '.join(mem_lines)}")

        # --- Secure ADS (TLS) check ---
        try:
            tls_result = self.scanner._check_secure_ads(quiet=True)
            if tls_result.get("available"):
                tls_ver = tls_result.get("tls_version", "Unknown")
                issues = tls_result.get("issues", [])
                if issues:
                    self.logger.display(
                        f"Secure ADS: available ({tls_ver}, {len(issues)} issue(s))"
                    )
                else:
                    self.logger.display(f"Secure ADS: available ({tls_ver})")
            else:
                self.logger.display("Secure ADS: not available")
        except Exception as e:
            self.logger.debug(f"Secure ADS check failed: {e}")

    def _show_state(self):
        """Show detailed PLC state, with EtherCAT master fallback.

        read_state() works on PLC runtimes (.1.1) but times out on
        EtherCAT subsystems (.2.1).  When it fails, fall back to reading
        the EtherCAT master AL state via ig=0x0006 on port 0xFFFF.
        """
        try:
            ads_state, device_state = self.conn.read_state()
            state_name = ADS_STATE_MAP.get(ads_state, f"UNKNOWN({ads_state})")

            self.logger.display("PLC State:")
            self.logger.display(f"  ADS State: {state_name} ({ads_state})")
            self.logger.display(f"  Device State: {device_state}")

        except Exception as e:
            self.logger.debug("read_state failed, trying EtherCAT master: %s", e)

            # Fallback: read EtherCAT master state from port 0xFFFF
            pyads = _get_pyads()
            master_conn = None
            try:
                master_conn = pyads.Connection(self.scanner.ams_netid, 0xFFFF)
                master_conn.open()
                master_conn.set_timeout(self.scanner.ads_timeout_ms)

                state_data = _read_raw(master_conn, ADS_IDX_GRP["ECAT_AL_STATE"], 0, 2)
                if state_data and len(state_data) >= 2:
                    raw_state = struct.unpack("<H", state_data)[0]
                    state_name = get_al_state_name(raw_state)
                    self.logger.display("EtherCAT Master State:")
                    self.logger.display(f"  AL State: {state_name}")

                    # Also show per-slave states for active ports
                    for port in range(1001, 1033):
                        try:
                            sl_data = _read_raw(
                                master_conn,
                                ADS_IDX_GRP["ECAT_AL_STATE"],
                                port,
                                2,
                            )
                            if sl_data and len(sl_data) >= 2:
                                sl_raw = struct.unpack("<H", sl_data)[0]
                                if sl_raw == 0:
                                    continue
                                sl_name = get_al_state_name(sl_raw)
                                self.logger.display(f"  Slave {port}: {sl_name}")
                        except Exception:
                            break
                else:
                    self.logger.fail(f"Error reading state: {e}")
            except Exception as e2:
                self.logger.debug("EtherCAT master state also failed: %s", e2)
                self.logger.fail(f"Error reading state: {e}")
            finally:
                if master_conn:
                    try:
                        master_conn.close()
                    except Exception as e:
                        self.logger.debug(f"master_conn.close(): {e}")

    def _set_state(self, new_state: str):
        """Set PLC state (DANGEROUS)"""
        if not getattr(self.args, "confirm", False):
            self.logger.fail("--set-state requires --confirm (DANGEROUS operation)")
            return

        state_map = {
            "RUN": 5,
            "STOP": 6,
            "RESET": 2,
            "CONFIG": 15,
            "RECONFIG": 16,
        }

        if new_state not in state_map:
            self.logger.fail(f"Unknown state: {new_state}")
            return

        try:
            self.logger.warning(f"Setting PLC state to {new_state}...")
            self.conn.write_control(state_map[new_state], 0, 0, ctypes.c_byte)
            self.logger.success(f"State set to {new_state}")

        except Exception as e:
            self.logger.debug("set state failed: %s", e)
            self.logger.fail(f"Error setting state: {e}")

    def _list_symbols(self):
        """List all symbols (names only)"""
        try:
            symbols = self.conn.get_all_symbols()
            self.logger.display(f"Found {len(symbols)} symbols:")

            # Apply filter if specified
            pattern = getattr(self.args, "symbol_filter", None)

            for sym in symbols[: self.scanner.max_symbols]:
                if pattern and not fnmatch.fnmatch(sym.name, pattern):
                    continue
                self.logger.display(f"  {sym.name} ({sym.symbol_type})")

            if len(symbols) > self.scanner.max_symbols:
                self.logger.display(f"  ... and {len(symbols) - self.scanner.max_symbols} more")

        except Exception as e:
            self.logger.debug("list symbols failed: %s", e)
            self.logger.fail(f"Error listing symbols: {e}")

    def _enumerate_symbols(self):
        """Enumerate symbols with values"""
        try:
            symbols = self.conn.get_all_symbols()
            pattern = getattr(self.args, "symbol_filter", None)

            rows = []
            count = 0

            for sym in symbols:
                if count >= self.scanner.max_symbols:
                    break

                if pattern and not fnmatch.fnmatch(sym.name, pattern):
                    continue

                try:
                    value = self.conn.read_by_name(sym.name)
                    value_str = self.scanner._format_value(value)
                except Exception as e:
                    self.logger.debug("enumerate symbols failed: %s", e)
                    value_str = f"<error: {e}>"

                rows.append([sym.name, str(sym.symbol_type), sym.size, value_str])
                count += 1

            headers = ["Name", "Type", "Size", "Value"]
            output_dir = getattr(self.args, "output", None)
            fmt = getattr(self.args, "format", "console") if output_dir else "console"
            export_data(
                rows, headers, fmt, output_dir, "ads_symbols", "ADS Symbols", logger=self.logger
            )

            self.logger.display(f"Enumerated {count} symbols")
            self.results["data"]["symbols"] = {"count": count, "exported": bool(output_dir)}

        except Exception as e:
            self.logger.debug("enumerate symbols failed: %s", e)
            self.logger.fail(f"Error enumerating symbols: {e}")

    def _read_symbol(self, name: str):
        """Read a specific symbol"""
        try:
            value = self.conn.read_by_name(name)
            self.logger.success(f"{name} = {self.scanner._format_value(value)}")
            self.results["data"]["symbol_read"] = {"name": name, "value": value}

        except Exception as e:
            self.logger.debug("read symbol failed: %s", e)
            self.logger.fail(f"Error reading {name}: {e}")

    def _write_symbol(self, arg: str):
        """Write to a symbol"""
        if not getattr(self.args, "confirm", False):
            self.logger.fail("--write-symbol requires --confirm")
            return

        try:
            name, value_str = arg.split(":", 1)
            # Try to parse value
            try:
                value = int(value_str)
            except ValueError as e:
                self.logger.debug("write symbol failed: %s", e)
                try:
                    value = float(value_str)
                except ValueError as e:
                    self.logger.debug("write symbol failed: %s", e)
                    value = value_str

            self.conn.write_by_name(name, value)
            self.logger.success(f"Wrote {value} to {name}")

        except ValueError as e:
            self.logger.debug("write symbol failed: %s", e)
            self.logger.fail("Format: NAME:VALUE")
        except Exception as e:
            self.logger.debug("write symbol failed: %s", e)
            self.logger.fail(f"Error writing: {e}")

    def _memory_read(self, arg: str):
        """Read memory directly"""
        try:
            parts = arg.split(":")
            if len(parts) != 3:
                self.logger.fail("Format: GROUP:OFFSET:SIZE")
                return

            group = int(parts[0], 0)  # Allows hex (0x...)
            offset = int(parts[1], 0)
            size = int(parts[2], 0)

            data = _read_raw(self.conn, group, offset, size)
            self.logger.success(f"Read {len(data)} bytes from {hex(group)}:{offset}")
            self.logger.display(f"  Data: {data.hex()}")

        except Exception as e:
            self.logger.debug("memory read failed: %s", e)
            self.logger.fail(f"Error reading memory: {e}")

    def _memory_write(self, arg: str):
        """Write memory directly"""
        if not getattr(self.args, "confirm", False):
            self.logger.fail("--memory-write requires --confirm")
            return

        try:
            parts = arg.split(":")
            if len(parts) != 3:
                self.logger.fail("Format: GROUP:OFFSET:DATA (hex)")
                return

            group = int(parts[0], 0)
            offset = int(parts[1], 0)
            data = bytes.fromhex(parts[2])

            _write_raw(self.conn, group, offset, data)
            self.logger.success(f"Wrote {len(data)} bytes to {hex(group)}:{offset}")

        except Exception as e:
            self.logger.debug("memory write failed: %s", e)
            self.logger.fail(f"Error writing memory: {e}")

    def _test_memory(self):
        """Test memory area accessibility"""
        self.logger.display("Testing memory access...")

        rows = []
        for area in _get_memory_areas():
            try:
                data = _read_raw(self.conn, area["group"], area["offset"], area["size"])
                rows.append([area["name"], hex(area["group"]), "OK", data.hex()])
            except Exception as e:
                self.logger.debug("test memory failed: %s", e)
                rows.append([area["name"], hex(area["group"]), "DENIED", str(e)[:30]])

        if rows:
            headers = ["Area", "Group", "Access", "Data/Error"]
            output_dir = getattr(self.args, "output", None)
            fmt = getattr(self.args, "format", "console") if output_dir else "console"
            export_data(
                rows,
                headers,
                fmt,
                output_dir,
                "ads_memory",
                "ADS Memory Access Test",
                logger=self.logger,
            )
        else:
            self.logger.display("No memory areas tested")

    def _scan_routes_nxc(self):
        """Scan AMS routes via SystemService (NXC wrapper)"""
        routes = self.scanner._scan_routes(self.conn)

        output_dir = getattr(self.args, "output", None)
        fmt = getattr(self.args, "format", "console") if output_dir else "console"

        if routes.get("discovered"):
            headers = ["Index", "Route Name", "Data Length"]
            rows = [[r["index"], r["name"], r["raw_length"]] for r in routes["discovered"]]
            export_data(
                rows, headers, fmt, output_dir, "ads_routes", "ADS Route Scan", logger=self.logger
            )

        if routes.get("discovered_by_probe"):
            headers = ["Net ID", "Extension", "Status"]
            rows = [[r["netid"], r["ext"], r["status"]] for r in routes["discovered_by_probe"]]
            export_data(
                rows,
                headers,
                fmt,
                output_dir,
                "ads_netid_probe",
                "ADS Net ID Probe",
                logger=self.logger,
            )

        if not routes.get("discovered") and not routes.get("discovered_by_probe"):
            self.logger.display("No routes or active Net IDs discovered")

    def _target_desc(self):
        """Get XML device description via SystemService (undocumented)"""
        result = self.scanner._get_target_desc(self.conn)

        if result.get("success"):
            self.logger.success("Target description retrieved")

            if result.get("parsed"):
                for key, value in result["parsed"].items():
                    self.logger.display(f"  {key}: {value}")

            # Export XML if output specified
            output_dir = getattr(self.args, "output", None)
            if output_dir and result.get("xml"):
                from oida.utils.export_utils import get_export_path

                xml_path = get_export_path("target_desc", "xml")
                if xml_path:
                    xml_path.write_text(result["xml"], encoding="utf-8")
            elif result.get("xml"):
                # Display XML to console
                self.logger.display(f"\n{result['xml']}")
        else:
            self.logger.fail(
                f"Failed to get target description: {result.get('error', 'Unknown error')}"
            )

    def _check_secure(self):
        """Check Secure ADS (TLS) availability and certificate (NXC wrapper)"""
        result = self.scanner._check_secure_ads()

        if result.get("available"):
            self.logger.success(f"Secure ADS available on port {result['port']}")
            self.logger.display(f"  TLS Version: {result.get('tls_version', 'Unknown')}")

            if result.get("issues"):
                self.logger.display(f"  Certificate issues: {len(result['issues'])}")
                for issue in result["issues"]:
                    self.logger.display(f"    - {issue}")
            else:
                self.logger.display("  Certificate: No issues found")

            # Store in results
            self.results["data"]["secure_ads"] = {
                "available": True,
                "port": result["port"],
                "tls_version": result.get("tls_version"),
                "cert_issues": result.get("issues", []),
            }
        else:
            self.logger.display(f"Secure ADS not available on port {result['port']}")
            if result.get("error"):
                self.logger.debug(f"  Error: {result['error']}")
            self.results["data"]["secure_ads"] = {"available": False}

    def _udp_discovery_nxc(self):
        """Perform UDP discovery to find ADS devices (NXC wrapper)"""
        result = self.scanner._udp_discovery(self.scanner.host)

        if result.get("success"):
            self.results["data"]["udp_discovery"] = result["devices"]

            if result["devices"]:
                headers = ["IP", "Hostname", "NetID", "TC Version", "OS"]
                rows = []
                for dev in result["devices"]:
                    rows.append(
                        [
                            dev.get("ip", ""),
                            dev.get("hostname", ""),
                            dev.get("netid", ""),
                            dev.get("tc_version", ""),
                            dev.get("os_version", "")[:30] if dev.get("os_version") else "",
                        ]
                    )

                output_dir = getattr(self.args, "output", None)
                fmt = getattr(self.args, "format", "console") if output_dir else "console"
                export_data(
                    rows,
                    headers,
                    fmt,
                    output_dir,
                    "ads_udp_discovery",
                    "ADS UDP Discovery",
                    logger=self.logger,
                )
        else:
            self.logger.display("UDP discovery found no devices")

    def _license_info_nxc(self):
        """Query TwinCAT license information (NXC wrapper)"""
        result = self.scanner._query_license_info(self.conn)

        if result.get("success"):
            self.results["data"]["license_info"] = result
            self.logger.success("License information retrieved")
        else:
            self.logger.fail(f"License query failed: {result.get('error', 'Unknown error')}")

    def _io_devices_nxc(self):
        """Enumerate I/O devices (NXC wrapper)"""
        result = self.scanner._enumerate_io_devices(self.conn)

        if result.get("success"):
            self.results["data"]["io_devices"] = result["devices"]

            if result["devices"]:
                headers = ["ID", "Name", "Type"]
                rows = [
                    [str(d.get("id", "")), d.get("name", ""), str(d.get("type", ""))]
                    for d in result["devices"]
                ]

                output_dir = getattr(self.args, "output", None)
                fmt = getattr(self.args, "format", "console") if output_dir else "console"
                export_data(
                    rows,
                    headers,
                    fmt,
                    output_dir,
                    "ads_io_devices",
                    "ADS I/O Devices",
                    logger=self.logger,
                )
        else:
            self.logger.display(
                f"I/O enumeration failed: {result.get('error', 'No devices found')}"
            )

    def _list_files_nxc(self, path: str):
        """List files via SystemService (NXC wrapper)"""
        result = self.scanner._list_files(self.conn, path)

        if result.get("success"):
            self.results["data"]["files"] = result["files"]

            if result["files"]:
                headers = ["Type", "Name", "Attributes"]
                rows = [
                    [
                        "DIR" if f.get("is_directory") else "FILE",
                        f.get("name", ""),
                        hex(f.get("attributes", 0)),
                    ]
                    for f in result["files"]
                ]

                output_dir = getattr(self.args, "output", None)
                fmt = getattr(self.args, "format", "console") if output_dir else "console"
                export_data(
                    rows,
                    headers,
                    fmt,
                    output_dir,
                    "ads_files",
                    f"ADS File Listing: {path}",
                    logger=self.logger,
                )
        else:
            self.logger.fail(f"File listing failed: {result.get('error', 'Unknown error')}")

    def _read_file_nxc(self, path: str):
        """Read file content (NXC wrapper)"""
        result = self.scanner._read_file(self.conn, path)

        if result.get("success"):
            self.results["data"]["file_content"] = {
                "path": path,
                "size": result["size"],
            }

            # Save to file if output specified
            output_dir = getattr(self.args, "output", None)
            if output_dir and result.get("data"):
                from oida.utils.common_types import safe_output_path

                filename = f"ads_file_{os.path.basename(path.replace(chr(92), '/'))}"
                os.makedirs(output_dir, exist_ok=True)
                try:
                    out_path = safe_output_path(filename, output_dir)
                except ValueError:
                    self.logger.fail(f"Path traversal detected in filename: {filename}")
                    return
                with open(out_path, "wb") as f:
                    f.write(result["data"])
                self.logger.success(f"Saved to: {out_path}")
            elif result.get("data"):
                # Display content
                try:
                    text = result["data"].decode("utf-8", errors="replace")
                    self.logger.display(f"Content:\n{text}")
                except Exception as e:
                    self.logger.debug("read file nxc failed: %s", e)
                    self.logger.display(f"Content (hex): {result['data'].hex()}")
        else:
            self.logger.fail(f"File read failed: {result.get('error', 'Unknown error')}")

    def _task_info_nxc(self):
        """Read PLC task runtime data (NXC wrapper for --task-info)"""
        result = self.scanner._read_task_data()

        if result.get("success"):
            self.results["data"]["task_info"] = result["tasks"]

            rows = []
            for t in result["tasks"]:
                cycle = f"{t['cycle_time_ms']:.2f} ms" if t.get("cycle_time_ms") else "?"
                prio = str(t.get("priority", "?"))
                rows.append([str(t["index"]), cycle, prio, t.get("raw_hex", "")[:32]])

            if rows:
                headers = ["Task", "Cycle Time", "Priority", "Raw (hex)"]
                output_dir = getattr(self.args, "output", None)
                fmt = getattr(self.args, "format", "console") if output_dir else "console"
                export_data(
                    rows,
                    headers,
                    fmt,
                    output_dir,
                    "ads_task_info",
                    "ADS Task Data",
                    logger=self.logger,
                )
        else:
            self.logger.fail(
                f"Task data read failed: {result.get('error', 'ig=0xF200 not supported')}"
            )

    def _foe_delete_nxc(self, spec: str):
        """Delete file on EtherCAT slave via FoE (NXC wrapper for --foe-delete)"""
        # Parse PORT:FILENAME
        parts = spec.split(":", 1)
        if len(parts) != 2:
            self.logger.fail("Invalid format. Use: PORT:FILENAME (e.g., '1001:systrace')")
            return

        try:
            port = int(parts[0])
        except ValueError:
            self.logger.fail(f"Invalid port number: {parts[0]}")
            return

        filename = parts[1]
        result = self.scanner._delete_file_foe(port, filename)

        self.results["data"]["foe_delete"] = result

        if not result.get("success"):
            hint = result.get("hint", "")
            self.logger.fail(f"FoE delete failed: {result.get('error', 'Unknown')}")
            if hint:
                self.logger.display(f"  Hint: {hint}")

    def _watch_symbol_nxc(self, spec: str):
        """Watch a PLC symbol for changes via ADS device notifications (NXC wrapper for --watch)"""
        import time

        pyads = _get_pyads()

        # Parse SYMBOL[:INTERVAL_MS]
        parts = spec.split(":", 1)
        symbol_name = parts[0]
        interval_ms = int(parts[1]) if len(parts) > 1 else 100

        ads_port = self.scanner._get_ads_port()
        self.logger.display(
            f"Watching symbol '{symbol_name}' (interval={interval_ms}ms, port={ads_port})..."
        )
        self.logger.display("Press Ctrl+C to stop.")

        values = []

        def notification_callback(notification, _symbol_name_bytes):
            """Callback for ADS notifications"""
            ts = time.strftime("%H:%M:%S")
            handle, timestamp, value = notification
            values.append({"time": ts, "value": value})
            self.logger.success(f"  [{ts}] {symbol_name} = {value}")

        try:
            conn = pyads.Connection(self.scanner.ams_netid, ads_port)
            conn.open()

            try:
                # Get symbol info to determine PLCTYPE
                info = conn.get_symbol(symbol_name)

                attr = pyads.NotificationAttrib(
                    length=info.size,
                    trans_mode=pyads.ADSTRANS_SERVERCYCLE,
                    max_delay=0,
                    cycle_time=interval_ms,
                )

                handles = conn.add_device_notification(symbol_name, attr, notification_callback)

                self.logger.display(f"  Notification registered (handle={handles})")

                # Wait until Ctrl+C
                while True:
                    time.sleep(0.5)

            except KeyboardInterrupt:
                self.logger.display(f"\n  Stopped watching. Collected {len(values)} values.")
            finally:
                try:
                    conn.del_device_notification(*handles)
                except Exception as e:
                    logger.debug(f"conn.del_device_notification(handles): {e}")
                conn.close()

        except AttributeError:
            # pyads version may not support get_symbol — fall back to polling
            self.logger.display("  Notification API not available, falling back to polling...")
            try:
                conn = pyads.Connection(self.scanner.ams_netid, ads_port)
                conn.open()
                try:
                    last_value = None
                    while True:
                        try:
                            value = conn.read_by_name(symbol_name)
                            if value != last_value:
                                ts = time.strftime("%H:%M:%S")
                                values.append({"time": ts, "value": value})
                                self.logger.success(f"  [{ts}] {symbol_name} = {value}")
                                last_value = value
                            time.sleep(interval_ms / 1000.0)
                        except KeyboardInterrupt:
                            break
                finally:
                    conn.close()
            except Exception as e:
                self.logger.fail(f"Watch failed: {e}")

            self.logger.display(f"\n  Stopped watching. Collected {len(values)} values.")

        except Exception as e:
            self.logger.fail(f"Watch failed: {e}")

        self.results["data"]["watch"] = {
            "symbol": symbol_name,
            "interval_ms": interval_ms,
            "values_collected": len(values),
        }

    def _read_registry_nxc(self, spec: str):
        """Read registry value (NXC wrapper)"""
        # Parse HIVE:KEY[:VALUE]
        parts = spec.split(":", 2)
        if len(parts) < 2:
            self.logger.fail("Invalid format. Use: HIVE:KEY[:VALUE]")
            return

        hive = parts[0]
        key = parts[1]
        value = parts[2] if len(parts) > 2 else None

        result = self.scanner._read_registry(self.conn, hive, key, value)

        if result.get("success"):
            self.results["data"]["registry"] = {
                "hive": hive,
                "key": key,
                "value": value,
                "type": result.get("type"),
                "decoded": result.get("decoded"),
            }
        else:
            self.logger.fail(f"Registry read failed: {result.get('error', 'Unknown error')}")

    def _download_program_nxc(self):
        """Download PLC program (NXC wrapper)"""
        result = self.scanner._download_plc_program(self.conn)

        if result.get("success"):
            self.results["data"]["program"] = {
                "symbol_count": result["symbol_count"],
                "symbol_size": result["symbol_size"],
                "datatype_size": result["datatype_size"],
            }

            # Save to files if output specified
            output_dir = getattr(self.args, "output", None)
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)

                if result.get("symbols"):
                    sym_path = os.path.join(output_dir, "symbols.bin")
                    with open(sym_path, "wb") as f:
                        f.write(result["symbols"])
                    self.logger.success(f"Symbols saved to: {sym_path}")

                if result.get("datatypes"):
                    dt_path = os.path.join(output_dir, "datatypes.bin")
                    with open(dt_path, "wb") as f:
                        f.write(result["datatypes"])
                    self.logger.success(f"Datatypes saved to: {dt_path}")
        else:
            self.logger.fail(f"Program download failed: {result.get('error', 'Unknown error')}")

    def _scan_ethercat_nxc(self):
        """Scan EtherCAT configuration (NXC wrapper)"""
        result = self.scanner._scan_ethercat(self.conn)

        if result.get("success"):
            self.results["data"]["ethercat"] = result

            if result.get("slaves"):
                headers = [
                    "Port",
                    "AL State",
                    "Device Name",
                    "Vendor ID",
                    "Vendor Name",
                    "Product Code",
                    "Serial",
                    "Revision",
                    "HW Version",
                    "SW Version",
                ]
                rows = []
                for s in result["slaves"]:
                    rows.append(
                        [
                            str(s.get("port", "")),
                            s.get("al_state", "-"),
                            s.get("device_name", "-"),
                            s.get("vendor_id", "-"),
                            s.get("vendor_name", "-"),
                            s.get("product_code", "-"),
                            s.get("serial", "-"),
                            s.get("revision", "-"),
                            s.get("hw_version", "-"),
                            s.get("sw_version", "-"),
                        ]
                    )

                output_dir = getattr(self.args, "output", None)
                fmt = getattr(self.args, "format", "console") if output_dir else "console"
                export_data(
                    rows,
                    headers,
                    fmt,
                    output_dir,
                    "ads_ethercat",
                    "EtherCAT Slaves",
                    logger=self.logger,
                )
        else:
            self.logger.display(f"EtherCAT scan: {result.get('error', 'No data')}")

    @staticmethod
    def _fmt_coe_value(obj):
        """Format a CoE SDO value for display."""
        data_hex = obj.get("data", "")
        size = obj.get("size", 0)
        if size == 0 or not data_hex:
            return ""
        try:
            raw = bytes.fromhex(data_hex)
        except ValueError as e:
            logger.debug(f"CoE value hex decode failed: {e}")
            return data_hex
        if size <= 4:
            val = int.from_bytes(raw, "little")
            if size == 1:
                return str(val)
            if size == 2:
                return f"0x{val:04X}" if val > 255 else str(val)
            return f"0x{val:08X}" if val > 0xFFFF else str(val)
        try:
            text = raw.decode("utf-8", errors="ignore").rstrip("\x00")
            if text and all(c.isprintable() or c.isspace() for c in text):
                return f'"{text}"'
        except Exception as e:
            logger.debug(f"CoE value UTF-8 decode failed: {e}")
        return data_hex

    def _scan_coe_nxc(self):
        """Scan CoE object dictionary on EtherCAT slaves (NXC wrapper).

        Discovers slave ports (or uses -P), then enumerates
        the full CoE dictionary on each slave via ADS bridge reads.
        """
        # Parse --coe-range override
        scan_ranges = self._get_coe_scan_ranges()
        if scan_ranges is False:
            return

        slave_ports = self._get_slave_ports()
        if slave_ports is None:
            return

        label = "custom CoE ranges" if scan_ranges else "CoE dictionary"
        self.logger.display(f"Scanning {label} on {len(slave_ports)} port(s)...")

        coe_results = self.scanner._scan_coe_via_ads(slave_ports, scan_ranges=scan_ranges)
        self.results["data"]["coe_dictionary"] = coe_results

        # Output per-slave table
        output_dir = getattr(self.args, "output", None)
        fmt = getattr(self.args, "format", "console") if output_dir else "console"

        for port, objects in coe_results.items():
            if not objects:
                continue

            slave_label = self._get_slave_label(port)

            headers = ["Index", "Sub", "Name", "Size", "Value", "Category"]
            rows = []
            for obj in objects:
                rows.append(
                    [
                        obj["index"],
                        str(obj["subindex"]),
                        obj.get("name", ""),
                        str(obj["size"]),
                        self._fmt_coe_value(obj),
                        obj.get("category", ""),
                    ]
                )

            title = f"CoE Dictionary — {slave_label} (port {port})"
            export_data(
                rows,
                headers,
                fmt,
                output_dir,
                f"ads_coe_port{port}",
                title,
                logger=self.logger,
            )

    def _scan_coe_access_nxc(self):
        """Scan CoE dictionary with access type detection (NXC wrapper).

        Like _scan_coe_nxc but additionally tests write access on each object,
        classifying them as RO/RW/WO. Requires --confirm.
        """
        if not getattr(self.args, "confirm", False):
            self.logger.fail("--scan-coe-access requires --confirm (writes to device)")
            return

        # Parse --coe-range override
        scan_ranges = self._get_coe_scan_ranges()
        if scan_ranges is False:
            return

        slave_ports = self._get_slave_ports()
        if slave_ports is None:
            return

        label = "custom CoE ranges + access" if scan_ranges else "CoE dictionary + access"
        self.logger.display(f"Scanning {label} on {len(slave_ports)} port(s)...")

        coe_results = self.scanner._scan_coe_via_ads(
            slave_ports, test_access=True, scan_ranges=scan_ranges
        )
        self.results["data"]["coe_access"] = coe_results

        # Output per-slave table with Access column
        output_dir = getattr(self.args, "output", None)
        fmt = getattr(self.args, "format", "console") if output_dir else "console"

        for port, objects in coe_results.items():
            if not objects:
                continue

            slave_label = self._get_slave_label(port)

            self.logger.display(f"CoE Access — {slave_label} (port {port}):")
            headers = ["Index", "Sub", "Name", "Size", "Value", "Access", "Category"]
            rows = []
            for obj in objects:
                rows.append(
                    [
                        obj["index"],
                        str(obj["subindex"]),
                        obj.get("name", ""),
                        str(obj["size"]),
                        self._fmt_coe_value(obj),
                        obj.get("access", "-"),
                        obj.get("category", ""),
                    ]
                )

            export_data(
                rows,
                headers,
                fmt,
                output_dir,
                f"ads_coe_access_port{port}",
                f"CoE Access (port {port})",
                logger=self.logger,
            )

    def _eeprom_dump_nxc(self):
        """Dump raw EEPROM from EtherCAT slaves (NXC wrapper)."""
        slave_ports = self._get_slave_ports()
        if slave_ports is None:
            return
        self.logger.display(f"Dumping EEPROM on {len(slave_ports)} slaves...")

        eeprom_results = self.scanner._dump_eeprom_via_ads(slave_ports)
        self.results["data"]["eeprom_dump"] = eeprom_results

        output_dir = getattr(self.args, "output", None)
        fmt = getattr(self.args, "format", "console") if output_dir else "console"

        for port, dump in eeprom_results.items():
            words = dump.get("words", [])
            header = dump.get("header", {})

            if not words:
                self.logger.display(f"\nEEPROM — Port {port}: no data")
                continue

            slave_label = self._get_slave_label(port)

            self.logger.display(f"EEPROM — {slave_label} (port {port}):")

            # Show parsed header
            if header:
                if "vendor_id" in header:
                    vendor_name = lookup_vendor(header["vendor_id"])
                    self.logger.display(f"  Vendor:   0x{header['vendor_id']:08X} ({vendor_name})")
                if "product_code" in header:
                    self.logger.display(f"  Product:  0x{header['product_code']:08X}")
                if "revision" in header:
                    self.logger.display(f"  Revision: 0x{header['revision']:08X}")
                if "serial" in header:
                    self.logger.display(f"  Serial:   0x{header['serial']:08X}")
                if "station_alias" in header:
                    self.logger.display(f"  Alias:    {header['station_alias']}")
                # Mailbox protocol flags (available when full SII header parsed)
                mbx_flags = header.get("mailbox_protocol_flags")
                if mbx_flags:
                    supported = [k for k, v in mbx_flags.items() if v]
                    if supported:
                        self.logger.display(f"  Mailbox:  {', '.join(supported)}")

            # Hex dump table
            headers_tbl = ["Address", "Data"]
            rows = []
            for w in words:
                rows.append([w["address"], w["data"]])

            export_data(
                rows,
                headers_tbl,
                fmt,
                output_dir,
                f"ads_eeprom_port{port}",
                f"EEPROM Dump (port {port})",
                logger=self.logger,
            )

    def _esc_registers_nxc(self):
        """Dump ESC registers from EtherCAT slaves (NXC wrapper)."""
        slave_ports = self._get_slave_ports()
        if slave_ports is None:
            return
        self.logger.display(f"Reading ESC registers on {len(slave_ports)} slave(s)...")

        esc_results = self.scanner._read_esc_registers_via_ads(slave_ports)
        self.results["data"]["esc_registers"] = esc_results

        output_dir = getattr(self.args, "output", None)
        fmt = getattr(self.args, "format", "console") if output_dir else "console"

        for port, port_data in esc_results.items():
            if "error" in port_data:
                self.logger.display(f"ESC Registers — Port {port}: {port_data['error']}")
                continue

            slave_label = self._get_slave_label(port)
            regs = port_data.get("registers", {})
            if not regs:
                continue

            self.logger.display(f"ESC Registers — {slave_label} (port {port}):")

            # Show decoded summary
            if "al_state" in port_data:
                state_str = port_data["al_state"]
                if port_data.get("al_error_flag"):
                    state_str += " (ERROR)"
                if "al_status_code" in port_data:
                    state_str += f" — {port_data['al_status_code']}"
                self.logger.display(f"  AL State: {state_str}")

            if "sync_managers" in port_data:
                for sm in port_data["sync_managers"]:
                    self.logger.display(
                        f"  SM{sm['sm']}: start={sm['start']} len={sm['length']} "
                        f"ctrl={sm['control']} status={sm['status']}"
                    )

            # Register table
            headers = ["Address", "Name", "Size", "Value/Data"]
            rows = []
            for addr in sorted(regs.keys()):
                r = regs[addr]
                if "value" in r and r["size"] <= 4:
                    val_str = (
                        f"0x{r['value']:0{r['size'] * 2}X}" if r["value"] > 255 else str(r["value"])
                    )
                else:
                    val_str = r["data"]
                rows.append([r["address"], r["name"], str(r["size"]), val_str])

            export_data(
                rows,
                headers,
                fmt,
                output_dir,
                f"ads_esc_regs_port{port}",
                f"ESC Registers (port {port})",
                logger=self.logger,
            )

    def _foe_read_nxc(self, spec):
        """Read file from EtherCAT slave via FoE (NXC wrapper).

        Parses PORT:FILENAME spec, reads file, saves or hex-dumps.
        """
        parts = spec.split(":", 1)
        if len(parts) != 2:
            self.logger.fail("--foe-read format: PORT:FILENAME (e.g., '1001:firmware.bin')")
            return
        try:
            port = int(parts[0])
        except ValueError:
            self.logger.fail(f"Invalid port number: {parts[0]}")
            return
        filename = parts[1]

        result = self.scanner._foe_read_via_ads(port, filename)
        self.results["data"]["foe_read"] = {
            "port": port,
            "filename": filename,
            "success": result["success"],
            "size": result.get("size", 0),
        }

        if result["success"]:
            data = result["data"]
            output_dir = getattr(self.args, "output", None)
            if output_dir:
                from oida.utils.common_types import safe_output_path

                os.makedirs(output_dir, exist_ok=True)
                safe_name = f"foe_port{port}_{os.path.basename(filename)}"
                try:
                    out_path = safe_output_path(safe_name, output_dir)
                except ValueError:
                    self.logger.fail(f"Path traversal detected in filename: {filename}")
                    return
                with open(out_path, "wb") as f:
                    f.write(data)
                self.logger.success(f"FoE: saved {len(data)} bytes to {out_path}")
            else:
                self.logger.success(f"FoE: received {len(data)} bytes from port {port}:{filename}")
                self.logger.display(f"  Data: {data.hex()}")
        else:
            msg = f"FoE read failed: {result.get('error', 'unknown')}"
            if result.get("hint"):
                msg += f" — {result['hint']}"
            self.logger.fail(msg)

    def _scan_foe_nxc(self):
        """Scan FoE support on all EtherCAT slaves (NXC wrapper).

        Downloads readable files and saves them to a temp directory.
        """
        slave_ports = self._get_slave_ports()
        if slave_ports is None:
            return
        self.logger.display(f"Scanning FoE support on {len(slave_ports)} slave(s)...")

        # Create temp dir for downloaded files
        save_dir = tempfile.mkdtemp(prefix="oida_foe_")
        self.logger.debug(f"FoE scan save directory: {save_dir}")
        foe_results = self.scanner._scan_foe_via_ads(slave_ports, save_dir=save_dir)
        self.results["data"]["foe_scan"] = foe_results
        self.results["data"]["foe_save_dir"] = save_dir

        output_dir = getattr(self.args, "output", None)
        fmt = getattr(self.args, "format", "console") if output_dir else "console"

        headers = ["Port", "FoE Support", "Files Found", "Notes"]
        rows = []
        total_files = 0
        for port in sorted(foe_results.keys()):
            info = foe_results[port]
            supported = "Yes" if info["supported"] else "No"
            readable_files = [f for f in info["files"] if f.get("readable")]
            file_count = len(readable_files)
            total_files += file_count
            notes = info.get("state_hint", "")
            rows.append([str(port), supported, str(file_count), notes])

        export_data(
            rows,
            headers,
            fmt,
            output_dir,
            "ads_foe_scan",
            "FoE Scan Results",
            logger=self.logger,
        )

        # Detail: list readable files per port with saved paths
        for port in sorted(foe_results.keys()):
            info = foe_results[port]
            readable = [f for f in info["files"] if f.get("readable")]
            if readable:
                slave_label = self._get_slave_label(port)
                file_headers = ["Filename", "Size", "Saved To"]
                file_rows = [[f["name"], str(f["size"]), f.get("path", "")] for f in readable]
                export_data(
                    file_rows,
                    file_headers,
                    fmt,
                    output_dir,
                    f"ads_foe_files_port{port}",
                    f"FoE Readable Files — {slave_label} (port {port})",
                    logger=self.logger,
                )

        if total_files > 0:
            self.logger.success(f"FoE: {total_files} file(s) saved to {save_dir}")

    def _foe_list_nxc(self, spec):
        """List accessible FoE files on a slave port (NXC wrapper).

        Downloads readable files and saves them to a temp directory.
        Spec: PORT or PORT:PATTERN1,PATTERN2,...
        """
        parts = spec.split(":", 1)
        try:
            port = int(parts[0])
        except ValueError:
            self.logger.fail(f"Invalid port number: {parts[0]}")
            return

        patterns = None
        if len(parts) > 1 and parts[1]:
            patterns = [p.strip() for p in parts[1].split(",") if p.strip()]

        self.logger.display(f"Probing FoE files on port {port}...")

        # Create temp dir for downloaded files
        save_dir = tempfile.mkdtemp(prefix="oida_foe_")
        self.logger.debug(f"FoE list save directory: {save_dir}")
        result = self.scanner._foe_list_via_ads(port, patterns, save_dir=save_dir)
        self.results["data"]["foe_list"] = result
        self.results["data"]["foe_save_dir"] = save_dir

        if result.get("error"):
            self.logger.fail(f"FoE list failed: {result['error']}")
            return

        output_dir = getattr(self.args, "output", None)
        fmt = getattr(self.args, "format", "console") if output_dir else "console"

        found = [f for f in result["files"] if not f.get("error")]
        if not found and not result["files"]:
            self.logger.display(f"  No FoE files found on port {port}")
            return

        headers = ["Filename", "Size", "Status", "Saved To"]
        rows = []
        for f in result["files"]:
            status = "OK" if not f.get("error") else f["error"]
            path = f.get("path", "")
            rows.append([f["name"], str(f["size"]) if f["size"] else "?", status, path])

        slave_label = self._get_slave_label(port)
        export_data(
            rows,
            headers,
            fmt,
            output_dir,
            f"ads_foe_list_port{port}",
            f"FoE Files — {slave_label} (port {port})",
            logger=self.logger,
        )

        file_count = len(found)
        if file_count > 0:
            self.logger.success(f"FoE: {file_count} file(s) saved to {save_dir}")

    def _foe_write_nxc(self, spec):
        """Write file to EtherCAT slave via FoE (NXC wrapper).

        Spec: PORT:LOCAL_PATH:REMOTE_NAME
        """
        parts = spec.split(":", 2)
        if len(parts) != 3:
            self.logger.fail(
                "--foe-write format: PORT:LOCAL_FILE:REMOTE_NAME (e.g., '1001:fw.bin:firmware.bin')"
            )
            return
        try:
            port = int(parts[0])
        except ValueError:
            self.logger.fail(f"Invalid port number: {parts[0]}")
            return
        local_path = parts[1]
        remote_name = parts[2]

        if not os.path.isfile(local_path):
            self.logger.fail(f"Local file not found: {local_path}")
            return

        with open(local_path, "rb") as f:
            data = f.read()

        self.logger.display(
            f"Writing {len(data)} bytes from '{local_path}' to port {port} as '{remote_name}'..."
        )
        result = self.scanner._foe_write_via_ads(port, remote_name, data)
        self.results["data"]["foe_write"] = {
            "port": port,
            "local_path": local_path,
            "remote_name": remote_name,
            "success": result["success"],
            "bytes_written": result.get("bytes_written", 0),
        }

        if result["success"]:
            self.logger.success(
                f"FoE: wrote {result['bytes_written']} bytes to port {port}:{remote_name}"
            )
        else:
            msg = f"FoE write failed: {result.get('error', 'unknown')}"
            if result.get("hint"):
                msg += f" — {result['hint']}"
            self.logger.fail(msg)

    def _scan_soe_nxc(self):
        """Scan SoE IDNs on EtherCAT slaves (NXC wrapper)."""
        slave_ports = self._get_slave_ports()
        if slave_ports is None:
            return
        self.logger.display(f"Scanning SoE IDNs on {len(slave_ports)} slave(s)...")

        soe_results = self.scanner._scan_soe_via_ads(slave_ports)
        self.results["data"]["soe_scan"] = soe_results

        output_dir = getattr(self.args, "output", None)
        fmt = getattr(self.args, "format", "console") if output_dir else "console"

        for port, port_idns in soe_results.items():
            if not port_idns:
                self.logger.display(f"\nSoE IDNs — Port {port}: no IDNs found (not a servo drive?)")
                continue

            slave_label = self._get_slave_label(port)

            headers = ["IDN", "Standard Name", "Device Name", "Size", "Value"]
            rows = []
            for idn in sorted(port_idns.keys()):
                info = port_idns[idn]
                val_str = ""
                if "value" in info:
                    val_str = str(info["value"])
                elif "value_hex" in info:
                    val_str = info["value_hex"]
                rows.append(
                    [
                        str(info["idn"]),
                        info.get("standard_name", ""),
                        info.get("device_name", ""),
                        str(info.get("value_size", "")),
                        val_str,
                    ]
                )

            export_data(
                rows,
                headers,
                fmt,
                output_dir,
                f"ads_soe_port{port}",
                f"SoE IDNs — {slave_label} (port {port})",
                logger=self.logger,
            )

    def _scan_fsoe_nxc(self):
        """Scan FSoE safety objects on EtherCAT slaves (NXC wrapper)."""
        slave_ports = self._get_slave_ports()
        if slave_ports is None:
            return
        self.logger.display(f"Scanning FSoE objects on {len(slave_ports)} slave(s)...")

        fsoe_results = self.scanner._scan_fsoe_via_ads(slave_ports)
        self.results["data"]["fsoe_scan"] = fsoe_results

        output_dir = getattr(self.args, "output", None)
        fmt = getattr(self.args, "format", "console") if output_dir else "console"

        # Summary table: which slaves support FSoE
        headers = ["Port", "FSoE", "Connections", "Objects Read", "Notes"]
        rows = []
        for port in sorted(fsoe_results.keys()):
            info = fsoe_results[port]
            supported = "Yes" if info["fsoe_supported"] else "No"
            conn = str(info["connection_count"]) if info["connection_count"] is not None else "-"
            obj_count = str(len(info["objects"]))
            notes = info.get("error", "") or ""
            rows.append([str(port), supported, conn, obj_count, notes])

        export_data(
            rows,
            headers,
            fmt,
            output_dir,
            "ads_fsoe_scan",
            "FSoE Scan Results",
            logger=self.logger,
        )

        # Detail per port: show all read objects
        for port in sorted(fsoe_results.keys()):
            info = fsoe_results[port]
            if not info["objects"]:
                continue

            slave_label = self._get_slave_label(port)
            obj_headers = ["Object", "Name", "Value"]
            obj_rows = []
            for obj in info["objects"]:
                idx_str = f"0x{obj['index']:04X}:{obj['subindex']}"
                name = obj["name"]
                if obj.get("error"):
                    val_str = f"[{obj['error']}]"
                elif "value" in obj:
                    val_str = str(obj["value"])
                else:
                    val_str = obj.get("raw", "")

                obj_rows.append([idx_str, name, val_str])

            export_data(
                obj_rows,
                obj_headers,
                fmt,
                output_dir,
                f"ads_fsoe_port{port}",
                f"FSoE Objects — {slave_label} (port {port})",
                logger=self.logger,
            )

    def _read_soe_nxc(self, spec):
        """Read SoE IDN from slave (NXC wrapper).

        Parses PORT:IDN[:DRIVE] spec, reads all elements.
        """
        parts = spec.split(":")
        if len(parts) < 2 or len(parts) > 3:
            self.logger.fail(
                "--read-soe format: PORT:IDN[:DRIVE] (e.g., '1001:135' or '1001:135:0')"
            )
            return
        try:
            port = int(parts[0])
            idn = int(parts[1])
            drive = int(parts[2]) if len(parts) == 3 else 0
        except ValueError:
            self.logger.fail(f"Invalid --read-soe values: {spec}")
            return

        result = self.scanner._read_soe_idn_via_ads(port, idn, drive=drive)
        self.results["data"]["soe_read"] = result

        if result.get("error"):
            self.logger.fail(f"SoE read failed: {result['error']}")
            return

        elements = result.get("elements", {})
        if not elements:
            self.logger.display(f"SoE IDN {idn} on port {port}: no elements readable")
            return

        std_name = SOE_STANDARD_IDNS.get(idn, "")
        self.logger.display(
            f"SoE IDN {idn} (drive {drive}) on port {port}"
            + (f" — {std_name}" if std_name else "")
            + ":"
        )

        for elem_id in sorted(elements.keys()):
            elem = elements[elem_id]
            display = elem["name"]
            if "text" in elem:
                display += f': "{elem["text"]}"'
            elif "value" in elem:
                display += f": {elem['value']}"
            else:
                display += f": {elem['data_hex']}"
            display += f" ({elem['size']}B)"
            self.logger.display(f"  [{elem_id}] {display}")

    def _fuzz_coe_nxc(self):
        """Fuzz CoE SDO objects on EtherCAT slaves (NXC wrapper).

        Requires --confirm. Discovers slaves, finds writable objects,
        and fuzzes them using the central fuzz() utility.
        """
        if not getattr(self.args, "confirm", False):
            self.logger.fail("--fuzz-coe requires --confirm (writes to device)")
            return

        iterations = getattr(self.args, "fuzz_iterations", 10)
        force_write = getattr(self.args, "force_write", False)

        # Parse --coe-range override
        scan_ranges = self._get_coe_scan_ranges()
        if scan_ranges is False:
            return

        slave_ports = self._get_slave_ports()
        if slave_ports is None:
            return

        mode = f"{iterations} iterations"
        if force_write:
            mode += ", force-write"
        self.logger.display(f"Fuzzing CoE SDOs on {len(slave_ports)} port(s) ({mode})...")

        fuzz_results = self.scanner._fuzz_coe_via_ads(
            slave_ports,
            iterations=iterations,
            scan_ranges=scan_ranges,
            force_write=force_write,
        )
        self.results["data"]["coe_fuzz"] = fuzz_results

        # Summary per port
        output_dir = getattr(self.args, "output", None)
        fmt = getattr(self.args, "format", "console") if output_dir else "console"

        for port, port_results in fuzz_results.items():
            if not port_results:
                continue

            headers = ["Index", "Sub", "Name", "Size", "Tested", "Accepted", "Rejected", "Crashes"]
            rows = []
            for r in port_results:
                rows.append(
                    [
                        r["index"],
                        str(r["subindex"]),
                        r["name"],
                        str(r["original_size"]),
                        str(r["iterations"]),
                        str(r["accepted"]),
                        str(r["rejected"]),
                        str(r["crashes"]),
                    ]
                )

            export_data(
                rows,
                headers,
                fmt,
                output_dir,
                f"ads_coe_fuzz_port{port}",
                f"CoE Fuzz Results (port {port})",
                logger=self.logger,
            )

    def _get_slave_ports(self):
        """Get EtherCAT slave ports, respecting -P for single-port targeting.

        Returns list of ports, or None on failure.
        Also stores the full scan result in self._ethercat_scan for slave
        label lookups (device names etc.).
        """
        user_port = getattr(self.args, "ads_port", None)
        if user_port:
            self._ethercat_scan = None
            return [int(user_port)]

        result = self.scanner._scan_ethercat(self.conn)
        if not result.get("success") or not result.get("slaves"):
            self.logger.fail(f"EtherCAT discovery failed: {result.get('error', 'no slaves found')}")
            return None
        self._ethercat_scan = result
        return [s["port"] for s in result["slaves"]]

    def _get_slave_label(self, port):
        """Get device name label for a slave port, or 'Port N' fallback."""
        scan = getattr(self, "_ethercat_scan", None)
        if scan and scan.get("slaves"):
            for s in scan["slaves"]:
                if s["port"] == port:
                    return s.get("device_name") or f"Port {port}"
        return f"Port {port}"

    def _get_coe_scan_ranges(self):
        """Parse --coe-range into scan ranges, or return None for defaults.

        Returns:
            list: Parsed ranges when --coe-range is valid
            None: When --coe-range is not specified (use defaults)
            False: When --coe-range is specified but invalid (caller should abort)
        """
        spec = getattr(self.args, "coe_range", None)
        if not spec:
            return None
        try:
            ranges = ADSScanner._parse_coe_ranges(spec)
            total = sum(end - start for start, end, _, _subs in ranges)
            sub_targets = sum(len(subs) for _, _, _, subs in ranges if subs is not None)
            desc = f"{total} indices"
            if sub_targets:
                desc += f", {sub_targets} specific subindices"
            self.logger.display(f"Using custom CoE ranges: {desc}")
            return ranges
        except ValueError as e:
            self.logger.fail(f"Invalid --coe-range: {e}")
            return False

    def _parse_coe_spec(self, spec, need_data=False):
        """Parse PORT:INDEX:SUB[:DATA] spec for CoE read/write.

        Returns (port, index, subindex, data_bytes) or None on error.
        """
        parts = spec.split(":")
        expected = 4 if need_data else 3
        if len(parts) < expected:
            label = "PORT:INDEX:SUB:DATA" if need_data else "PORT:INDEX:SUB"
            self.logger.fail(f"Invalid format. Use: {label}")
            return None

        try:
            port = int(parts[0])
            index = int(parts[1], 0)  # accept 0x prefix
            sub = int(parts[2], 0)
        except ValueError as e:
            self.logger.fail(f"Invalid number in spec: {e}")
            return None

        data = None
        if need_data:
            try:
                data = bytes.fromhex(parts[3])
            except ValueError:
                self.logger.fail(f"Invalid hex data: '{parts[3]}'")
                return None

        return (port, index, sub, data)

    def _read_coe_nxc(self, spec):
        """Read a single CoE SDO object via ADS (NXC wrapper)."""
        parsed = self._parse_coe_spec(spec)
        if not parsed:
            return
        port, index, sub, _ = parsed

        pyads = _get_pyads()
        conn = None
        try:
            conn = pyads.Connection(self.scanner.ams_netid, port)
            conn.open()
            conn.set_timeout(self.scanner.ads_timeout_ms)

            data = _read_coe_sdo(conn, index, sub)
            if data is None:
                self.logger.fail(f"Object 0x{index:04X}:{sub} not found on port {port}")
                return

            name = get_coe_object_name(index, sub)
            self.logger.display(f"CoE Read — port {port}, {name}:")
            self.logger.display(f"  Index:    0x{index:04X}:{sub}")
            self.logger.display(f"  Size:     {len(data)} bytes")
            self.logger.display(f"  Hex:      {data.hex()}")

            if len(data) <= 4:
                val = int.from_bytes(data, "little")
                self.logger.display(f"  Value:    {val} (0x{val:X})")
            else:
                try:
                    text = data.decode("utf-8", errors="ignore").rstrip("\x00")
                    if text and all(c.isprintable() or c.isspace() for c in text):
                        self.logger.display(f'  String:   "{text}"')
                except Exception as e:
                    self.logger.debug(f"CoE read: UTF-8 decode of result failed: {e}")

            self.results["data"]["coe_read"] = {
                "port": port,
                "index": f"0x{index:04X}",
                "subindex": sub,
                "name": name,
                "size": len(data),
                "data": data.hex(),
            }

        except Exception as e:
            self.logger.fail(f"CoE read failed: {e}")
        finally:
            if conn:
                try:
                    conn.close()
                except Exception as e:
                    self.logger.debug(f"conn.close(): {e}")

    def _write_coe_nxc(self, spec):
        """Write a CoE SDO object via ADS (NXC wrapper). Requires --confirm."""
        parsed = self._parse_coe_spec(spec, need_data=True)
        if not parsed:
            return
        port, index, sub, data = parsed

        name = get_coe_object_name(index, sub)
        self.logger.display(
            f"Writing {len(data)} bytes to CoE 0x{index:04X}:{sub} ({name}) on port {port}"
        )
        self.logger.display(f"  Data: {data.hex()}")

        pyads = _get_pyads()
        conn = None
        try:
            conn = pyads.Connection(self.scanner.ams_netid, port)
            conn.open()
            conn.set_timeout(self.scanner.ads_timeout_ms)

            offset = encode_sdo_offset(index, sub)
            _write_raw(conn, 0xF302, offset, data)

            self.logger.success(f"Write OK: 0x{index:04X}:{sub} on port {port}")
            self.results["data"]["coe_write"] = {
                "port": port,
                "index": f"0x{index:04X}",
                "subindex": sub,
                "name": name,
                "size": len(data),
                "data": data.hex(),
            }

        except Exception as e:
            self.logger.fail(f"CoE write failed: {e}")
        finally:
            if conn:
                try:
                    conn.close()
                except Exception as e:
                    self.logger.debug(f"conn.close(): {e}")

    def _add_route_nxc(self, spec: str):
        """Add AMS route (NXC wrapper)"""
        # NetID has 6 parts (x.x.x.x.x.x), IP has 4 parts
        # So we need to find where NetID ends and IP begins
        # Format: "192.168.1.50.1.1:192.168.1.50" or "192.168.1.50.1.1:192.168.1.50:routename"
        all_parts = spec.split(":")
        if len(all_parts) < 2:
            self.logger.fail("Invalid format. Use: NETID:IP[:NAME]")
            return

        netid = all_parts[0]
        ip = all_parts[1]
        name = all_parts[2] if len(all_parts) > 2 else "oida"

        result = self.scanner._add_route(self.conn, netid, ip, name)

        if result.get("success"):
            self.logger.success(f"Route added: {netid} -> {ip}")
            self.results["data"]["route_added"] = {
                "netid": netid,
                "ip": ip,
                "name": name,
            }
        else:
            self.logger.fail(f"Route add failed: {result.get('error', 'Unknown error')}")

    def _scan_ports(self, extended: bool = False):
        """Scan AMS service ports over existing TCP connection.

        Uses timeout-based classification to distinguish active services from
        false positives (pyads.Connection.open() always succeeds because it
        registers with the AMS router, not the target service).

        Args:
            extended: If True, scan all known AMS service ports.
                     If False, scan only common PLC runtime ports.
        """
        port_map = AMS_SERVICE_PORTS if extended else ADS_PORT_MAP
        self.logger.display(
            f"Scanning {'extended' if extended else 'common'} ADS ports ({len(port_map)} ports)..."
        )
        self.logger.debug(
            f"Port scan: AMS Net ID={self.scanner.ams_netid}, ports={list(port_map.values())}"
        )
        pyads = _get_pyads()

        port_progress = ProgressTracker(
            len(port_map),
            threshold=1.0,
            interval=0.5,
            logger=self.logger,
            show=True,
        )

        rows = []
        for port_name, port_num in port_map.items():
            port_progress.update()
            self.logger.debug(f"Probing port {port_num} ({port_name})...")
            result = _probe_netid(
                pyads,
                self.scanner.ams_netid,
                port_num,
                timeout_ms=self.scanner.ads_timeout_ms,
                master_fallback=False,
            )

            if result["type"] == "broken":
                self.logger.debug(f"AMS router connection lost at port {port_num}")
                break

            if result["active"]:
                status = "Available" if result["type"] == "plc" else "Active"
                self.logger.debug(
                    f"Port {port_num} ({port_name}): ACTIVE type={result['type']}, detail={result['detail']}"
                )
                self.logger.success(f"{port_name} ({port_num}): {result['detail']}")
                rows.append([port_name, str(port_num), status, result["detail"]])
            else:
                self.logger.debug(f"{port_name} ({port_num}): {result['detail']}")
                rows.append([port_name, str(port_num), "No Service", "-"])

        port_progress.finish()

        if rows:
            headers = ["Port Name", "Port", "Status", "Device"]
            output_dir = getattr(self.args, "output", None)
            fmt = getattr(self.args, "format", "console") if output_dir else "console"
            export_data(
                rows, headers, fmt, output_dir, "ads_ports", "ADS Port Scan", logger=self.logger
            )

    def _test_write_access(self):
        """Test write access to symbols (safe - writes same value back)"""
        self.logger.display("Testing write access...")

        try:
            symbols = self.conn.get_all_symbols()
            rows = []

            for sym in symbols[: self.scanner.max_symbols]:
                try:
                    value = self.conn.read_by_name(sym.name)
                    self.conn.write_by_name(sym.name, value)
                    rows.append([sym.name, str(sym.symbol_type), "Writable"])
                except Exception as e:
                    self.logger.debug("test write access failed: %s", e)
                    rows.append([sym.name, str(sym.symbol_type), "Read-only"])

            writable_count = sum(1 for r in rows if r[2] == "Writable")
            self.logger.display(
                f"Found {writable_count} writable symbols out of {len(rows)} tested"
            )

            if rows:
                headers = ["Symbol", "Type", "Access"]
                output_dir = getattr(self.args, "output", None)
                fmt = getattr(self.args, "format", "console") if output_dir else "console"
                export_data(
                    rows,
                    headers,
                    fmt,
                    output_dir,
                    "ads_write_access",
                    "ADS Write Access Test",
                    logger=self.logger,
                )

        except Exception as e:
            self.logger.debug("test write access failed: %s", e)
            self.logger.fail(f"Error testing write access: {e}")

    def _handle_fuzz(self):
        """Handle fuzzing operations"""
        mode = getattr(self.args, "fuzz", "symbols")

        if not getattr(self.args, "confirm", False):
            self.logger.fail("--fuzz requires --confirm (DANGEROUS)")
            return

        iterations = getattr(self.args, "fuzz_iterations", 10)
        self.logger.display(f"Fuzzing mode: {mode} ({iterations} iterations)")

        if mode in ["symbols", "all"]:
            fuzz_symbol = getattr(self.args, "fuzz_symbol", None)
            if fuzz_symbol:
                self._fuzz_symbol(fuzz_symbol, iterations)
            else:
                self._fuzz_all_writable_symbols(iterations)

    def _fuzz_symbol(self, symbol_name: str, iterations: int):
        """Fuzz a single symbol"""
        import time
        from ...utils.fuzzer import fuzz

        target_id = f"symbol:{symbol_name}"

        def read_value():
            value = self.conn.read_by_name(symbol_name)
            if isinstance(value, bool):
                return bytes([1 if value else 0])
            elif isinstance(value, int):
                return value.to_bytes(4, "little", signed=True)
            elif isinstance(value, float):
                return struct.pack("<f", value)
            elif isinstance(value, bytes):
                return value
            else:
                return str(value).encode()

        def write_value(data):
            try:
                orig = self.conn.read_by_name(symbol_name)
                if isinstance(orig, bool):
                    value = bool(data[0]) if data else False
                elif isinstance(orig, int):
                    value = int.from_bytes(data[:4].ljust(4, b"\x00"), "little", signed=True)
                elif isinstance(orig, float):
                    value = struct.unpack("<f", data[:4].ljust(4, b"\x00"))[0]
                else:
                    return False
                self.conn.write_by_name(symbol_name, value)
                return True
            except Exception as e:
                self.logger.debug("write value failed: %s", e)
                return False

        original = read_value()
        successful, failed, anomalies, crashes = 0, 0, 0, 0
        sym_progress = ProgressTracker(
            iterations,
            threshold=1.0,
            interval=0.5,
            logger=self.logger,
            show=True,
        )

        for payload, _mutation_desc in fuzz(original, count=iterations):
            sym_progress.update()
            try:
                if write_value(payload):
                    successful += 1
                    readback = read_value()
                    if readback != payload and readback != original:
                        anomalies += 1
                else:
                    failed += 1
            except Exception as e:
                self.logger.debug("write value failed: %s", e)
                crashes += 1
            time.sleep(ADS_FUZZ_SYMBOL_DELAY)

        sym_progress.finish()

        if original:
            write_value(original)

        status = "+" if crashes == 0 and anomalies == 0 else "!"
        self.logger.display(
            f"  [{status}] {target_id}: {successful + failed} tests, "
            f"{successful} writes, {anomalies} anomalies, {crashes} crashes"
        )

        if crashes > 0:
            self.logger.warning("    CRASHES DETECTED!")

    def _fuzz_all_writable_symbols(self, iterations: int):
        """Fuzz all writable symbols"""
        try:
            symbols = self.conn.get_all_symbols()
            writable = []

            for sym in symbols[: self.scanner.max_symbols]:
                try:
                    value = self.conn.read_by_name(sym.name)
                    self.conn.write_by_name(sym.name, value)
                    writable.append(sym.name)
                except Exception as e:
                    self.logger.debug("fuzz all writable symbols failed: %s", e)
                    pass

            self.logger.display(f"Fuzzing {len(writable)} writable symbols")

            for sym_name in writable:
                self._fuzz_symbol(sym_name, iterations)

        except Exception as e:
            self.logger.debug("fuzz all writable symbols failed: %s", e)
            self.logger.fail(f"Error during fuzzing: {e}")

    def cleanup(self):
        """Cleanup ADS connection"""
        if self._connection:
            try:
                self.scanner.disconnect(self._connection)
            except Exception as e:
                self.logger.debug(f"Cleanup error: {e}")

    @staticmethod
    def check_dependencies() -> bool:
        """Check if pyads is available"""
        return _pyads.is_available
