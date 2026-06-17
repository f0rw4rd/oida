#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
NXC-Style S7 Connection Class

Auto-executing connection class that follows the NXC pattern.
"""

from typing import List

from ...connection import NetworkConnection
from .scanner import Snap7Scanner, _get_block_types
from .constants import S7MemoryArea

import logging

logger = logging.getLogger(__name__)


class s7(NetworkConnection):
    """NXC-style Snap7 scanner (callable)"""

    def __init__(self, args, db, host):
        self.protocol_name = "S7"
        self.default_port = 102
        super().__init__(args, db, host)

    # Note: proto_logger() inherited from NetworkConnection base class

    def proto_flow(self):
        """Main Snap7 workflow with action support"""
        self.logger.debug("proto_flow: %s:%s", self.host, getattr(self.args, "port", 102))

        args_dict = self._convert_args_to_dict()
        self.scanner = Snap7Scanner(args_dict)

        self.create_conn_obj()
        if not self.conn:
            self.logger.fail(f"Failed to connect to {self.host}")
            self.results["success"] = False
            self.results["error"] = "Connection failed"
            return

        # Check for action commands vs regular scan
        if self._has_action():
            self._execute_action()
        else:
            # Always run discovery on a basic scan. Slot auto-detection only
            # enumerates rack/slot order codes + firmware; it does NOT perform
            # the security analysis (protection level, PUT/GET, encryption, ...)
            # that lives in scanner.discover(), so discover() runs
            # unconditionally regardless of whether the slot was auto-detected.
            self._execute_scan()

    def create_conn_obj(self):
        """Create Snap7 connection"""
        import os

        self.logger.info(f"Connecting via ISO-TSAP (TCP/{self.args.port})")
        self.conn = self.scanner.connect()
        if self.conn:
            self.logger.debug(f"Connected to Siemens S7 device at {self.ip}:{self.args.port}")
            self.results["data"]["device_info"] = {"connected": True}

            # Smart -P: if password value is a file path, brute-force with it
            password = getattr(self.args, "password", None)
            if password and os.path.isfile(password):
                from ...utils.login_scanner import format_wordlist_source

                self.logger.display(f"Password file detected: {format_wordlist_source(password)}")
                result = self.scanner.bruteforce_password(self.conn, wordlist_path=password)
                if result and result.get("success"):
                    self.results["data"]["password_found"] = result.get("password")
                self._store_action_result(result)
        else:
            self.logger.fail(f"Connection failed to {self.ip}:{self.args.port}")

    def _execute_scan(self):
        """Execute Snap7 scanning (security analysis + discovery)."""
        self.logger.debug("Executing scan")
        if not self.conn:
            return
        scan_results = self.scanner.discover(self.conn)
        self.results["data"]["scan_results"] = scan_results

    def _has_action(self) -> bool:
        """Check if an action command was requested"""
        action_attrs = [
            # CPU Control
            "cpu_stop",
            "cpu_start",
            "cpu_hot_start",
            "copy_ram_to_rom",
            "compress",
            # Block Ops
            "list_blocks",
            "list_blocks_of_type",
            "upload_db",
            "upload_block",
            "download_db",
            "delete_block",
            # Memory Read
            "read_inputs",
            "read_outputs",
            "read_markers",
            "read_timers",
            "read_counters",
            "read_db",
            "dump_db",
            # Memory Write
            "write_db",
            "write_markers",
            "write_outputs",
            "write_inputs",
            "write_timers",
            "write_counters",
            "db_fill",
            # DateTime
            "get_datetime",
            "set_datetime",
            "sync_datetime",
            # Info
            "info",
            "list_szl",
            "enumerate_szl",
            "read_szl_id",
            # Block Info
            "get_block_info",
            # Discovery
            "enumerate_dbs",
            "test_memory_areas",
            "scan_programs",
            # Auth
            "null_password",
            "default_creds",
            "brute",
            "logout",
            # Audit
            "audit",
            "audit_quick",
            # Fuzzing
            "fuzz",
            # Monitor
            "monitor",
        ]
        for attr in action_attrs:
            val = getattr(self.args, attr, None)
            if val is not None and val is not False:
                return True
        return False

    # Actions that modify PLC state and require --confirm
    DANGEROUS_ACTIONS = frozenset(
        {
            "cpu_stop",
            "cpu_start",
            "cpu_hot_start",
            "copy_ram_to_rom",
            "compress",
            "download_db",
            "delete_block",
            "write_db",
            "write_markers",
            "write_outputs",
            "write_inputs",
            "write_timers",
            "write_counters",
            "db_fill",
            "set_datetime",
            "sync_datetime",
            # Brute-force probes trip Siemens account-lockout / SCALANCE SIEM.
            "brute",
            "default_creds",
            # --audit issues a sequence of writes against the PLC. Operator
            # opted into a confirm-gated audit on 2026-06-03.
            "audit",
            "audit_quick",
        }
    )

    def _require_confirm(self, action: str) -> bool:
        """Check --confirm flag for dangerous operations. Returns True if allowed."""
        if action not in self.DANGEROUS_ACTIONS:
            return True
        if getattr(self.args, "confirm", False):
            return True
        self.logger.fail(
            f"--{action.replace('_', '-')} requires --confirm flag (DANGEROUS operation)"
        )
        return False

    def _execute_action(self):
        """Execute requested action command using dispatch table pattern"""
        self.logger.debug("Executing action")
        # Simple boolean actions: attr -> (message, scanner_method)
        simple_actions = {
            "cpu_stop": ("Executing CPU STOP...", "cpu_stop"),
            "cpu_start": ("Executing CPU COLD START...", "cpu_cold_start"),
            "cpu_hot_start": ("Executing CPU HOT START...", "cpu_hot_start"),
            "copy_ram_to_rom": ("Copying RAM to ROM...", "copy_ram_to_rom"),
            "compress": ("Compressing memory...", "compress_memory"),
            "list_blocks": ("Listing blocks...", "list_blocks"),
            "get_datetime": ("Getting PLC datetime...", "get_plc_datetime"),
            "sync_datetime": ("Syncing PLC datetime with host...", "sync_plc_datetime"),
            "info": ("Getting device info...", "info_action"),
            "enumerate_dbs": ("Enumerating data blocks...", "enumerate_dbs_action"),
            "test_memory_areas": (
                "Testing memory area access...",
                "test_memory_areas_action",
            ),
            "scan_programs": ("Scanning programs...", "scan_programs_action"),
            "list_szl": ("Listing SZL IDs...", "list_szl_ids"),
            "enumerate_szl": ("Enumerating SZL data...", "enumerate_szl"),
        }

        # Check simple boolean actions first
        for attr, (message, method_name) in simple_actions.items():
            if getattr(self.args, attr, False):
                if not self._require_confirm(attr):
                    return
                self.logger.display(message)
                result = getattr(self.scanner, method_name)(self.conn)
                self._store_action_result(result)
                return

        # Check complex actions that need special handling
        result = self._execute_complex_action()
        if result is not None:
            self._store_action_result(result)

    def _store_action_result(self, result):
        """Store action result in results dict"""
        if result:
            self.results["data"]["action_result"] = result
            if not result.get("success", True):
                self.results["success"] = False

    def _execute_complex_action(self):
        """Execute complex actions that need parameter parsing or special handling"""
        # Block operations with parameters
        if getattr(self.args, "list_blocks_of_type", None):
            block_type = self.args.list_blocks_of_type
            self.logger.display(f"Listing {block_type} blocks...")
            return self.scanner.list_blocks_of_type(self.conn, block_type)

        if getattr(self.args, "upload_db", None) is not None:
            return self._action_upload_db()

        if getattr(self.args, "upload_block", None):
            return self._action_upload_block()

        if getattr(self.args, "download_db", None) is not None:
            if not self._require_confirm("download_db"):
                return None
            return self._action_download_db()

        if getattr(self.args, "delete_block", None):
            if not self._require_confirm("delete_block"):
                return None
            return self._action_delete_block()

        # Memory read operations
        if getattr(self.args, "read_inputs", None):
            return self._action_read_memory("read_inputs", "inputs")

        if getattr(self.args, "read_outputs", None):
            return self._action_read_memory("read_outputs", "outputs")

        if getattr(self.args, "read_markers", None):
            return self._action_read_memory("read_markers", "markers")

        if getattr(self.args, "read_timers", None):
            return self._action_read_memory("read_timers", "timers")

        if getattr(self.args, "read_counters", None):
            return self._action_read_memory("read_counters", "counters")

        if getattr(self.args, "read_db", None):
            return self._action_read_db()

        if getattr(self.args, "dump_db", None) is not None:
            db_num = self.args.dump_db
            self.logger.display(f"Dumping DB{db_num}...")
            return self.scanner.dump_db(self.conn, db_num)

        # Memory write operations
        if getattr(self.args, "write_db", None):
            if not self._require_confirm("write_db"):
                return None
            return self._action_write_db()

        if getattr(self.args, "write_markers", None):
            if not self._require_confirm("write_markers"):
                return None
            return self._action_write_memory("write_markers", "M")

        if getattr(self.args, "write_outputs", None):
            if not self._require_confirm("write_outputs"):
                return None
            return self._action_write_memory("write_outputs", "Q")

        if getattr(self.args, "write_inputs", None):
            if not self._require_confirm("write_inputs"):
                return None
            return self._action_write_memory("write_inputs", "I")

        if getattr(self.args, "write_timers", None):
            if not self._require_confirm("write_timers"):
                return None
            return self._action_write_memory("write_timers", "T")

        if getattr(self.args, "write_counters", None):
            if not self._require_confirm("write_counters"):
                return None
            return self._action_write_memory("write_counters", "C")

        if getattr(self.args, "db_fill", None):
            if not self._require_confirm("db_fill"):
                return None
            return self._action_db_fill()

        # Date/Time operations
        if getattr(self.args, "set_datetime", None):
            if not self._require_confirm("set_datetime"):
                return None
            return self._action_set_datetime()

        # SZL operations
        if getattr(self.args, "read_szl_id", None):
            return self._action_read_szl()

        # Block info
        if getattr(self.args, "get_block_info", None):
            return self._action_get_block_info()

        # Auth operations
        if getattr(self.args, "logout", False):
            self.logger.display("Logging out from session...")
            self.scanner.clear_session(self.conn)
            self.logger.success("Logged out (session password cleared)")
            return {"success": True, "action": "logout"}

        if getattr(self.args, "null_password", False):
            result = self.scanner.test_null_password(self.conn)
            if result and result.get("success"):
                self.results["data"]["password_found"] = result.get("password")
            return result

        if getattr(self.args, "default_creds", False):
            if not self._require_confirm("default_creds"):
                return None
            return self._action_default_creds()

        if getattr(self.args, "brute", False):
            if not self._require_confirm("brute"):
                return None
            return self._action_brute()

        # Audit mode -- issues a sequence of unauthenticated writes against
        # the PLC; require --confirm (DESIGN call 2026-06-03).
        if getattr(self.args, "audit", False) or getattr(self.args, "audit_quick", False):
            quick = getattr(self.args, "audit_quick", False)
            action = "audit_quick" if quick else "audit"
            if not self._require_confirm(action):
                return None
            return self.scanner.audit(self.conn, quick=quick)

        # Monitor mode
        if getattr(self.args, "monitor", None):
            return self._action_monitor()

        # Fuzzing
        if getattr(self.args, "fuzz", None):
            self._handle_fuzz()
            return None  # Fuzz handles its own results

        return None

    def _action_upload_db(self):
        """Handle --upload-db action"""
        db_num = self.args.upload_db
        output_file = getattr(self.args, "output_file", None)
        self.logger.display(f"Uploading DB{db_num}...")
        return self.scanner.upload_db(self.conn, db_num, output_file)

    def _action_upload_block(self):
        """Handle --upload-block action"""
        block_spec = self.args.upload_block
        parts = block_spec.split(":")
        if len(parts) != 2:
            self.logger.fail("Invalid format. Use TYPE:NUM (e.g., FB:1)")
            self.results["success"] = False
            return None
        block_type, block_num = parts[0].upper(), int(parts[1])
        output_file = getattr(self.args, "output_file", None)
        self.logger.display(f"Uploading {block_type}{block_num}...")
        return self.scanner.upload_full_block(self.conn, block_type, block_num, output_file)

    def _action_download_db(self):
        """Handle --download-db action"""
        import os

        from ...utils.common_types import safe_file_path

        input_file = self.args.download_db
        db_num = getattr(self.args, "db_target", None)
        if db_num is None:
            self.logger.fail("--db-target NUM required for --download-db")
            self.results["success"] = False
            return None
        try:
            validated_path = safe_file_path(input_file, base_dir=os.getcwd())
            with open(validated_path, "rb") as f:
                data = f.read()
            self.logger.display(f"Downloading {len(data)} bytes to DB{db_num}...")
            return self.scanner.download_db(self.conn, db_num, data)
        except ValueError as e:
            self.logger.fail(f"Unsafe file path: {e}")
            self.results["success"] = False
            return None
        except FileNotFoundError:
            self.logger.fail(f"File not found: {input_file}")
            self.results["success"] = False
            return None

    def _action_delete_block(self):
        """Handle --delete-block action"""
        block_spec = self.args.delete_block
        parts = block_spec.split(":")
        if len(parts) != 2:
            self.logger.fail("Invalid format. Use TYPE:NUM (e.g., DB:10)")
            self.results["success"] = False
            return None
        block_type, block_num = parts[0].upper(), int(parts[1])
        self.logger.display(f"Deleting {block_type}{block_num}...")
        return self.scanner.delete_block(self.conn, block_type, block_num)

    def _action_read_memory(self, arg_name: str, area_name: str):
        """Handle memory read actions (inputs, outputs, markers, timers, counters)"""
        start, size = self._parse_range(getattr(self.args, arg_name))
        self.logger.display(f"Reading {area_name} {start}:{size}...")
        return getattr(self.scanner, arg_name)(self.conn, start, size)

    def _action_read_db(self):
        """Handle --read-db action"""
        parts = self.args.read_db.split(":")
        if len(parts) != 3:
            self.logger.fail("Invalid format. Use DB:START:SIZE (e.g., 1:0:100)")
            self.results["success"] = False
            return None
        db, start, size = int(parts[0]), int(parts[1]), int(parts[2])
        self.logger.display(f"Reading DB{db} {start}:{size}...")
        return self.scanner.read_db_area(self.conn, db, start, size)

    def _action_write_db(self):
        """Handle --write-db action"""
        parts = self.args.write_db.split(":")
        if len(parts) != 3:
            self.logger.fail("Invalid format. Use DB:START:HEXDATA (e.g., 1:0:DEADBEEF)")
            self.results["success"] = False
            return None
        db, start, hex_data = int(parts[0]), int(parts[1]), parts[2]
        data = bytes.fromhex(hex_data)
        self.logger.display(f"Writing {len(data)} bytes to DB{db}...")
        return self.scanner.write_db_area(self.conn, db, start, data)

    def _action_write_memory(self, arg_name: str, prefix: str):
        """Handle memory write actions (markers, outputs, inputs, timers, counters)"""
        parts = getattr(self.args, arg_name).split(":")
        if len(parts) != 2:
            self.logger.fail("Invalid format. Use START:HEXDATA")
            self.results["success"] = False
            return None
        start, hex_data = int(parts[0]), parts[1]
        data = bytes.fromhex(hex_data)
        self.logger.display(f"Writing {len(data)} bytes to {prefix}{start}...")
        return getattr(self.scanner, arg_name)(self.conn, start, data)

    def _action_db_fill(self):
        """Handle --db-fill action"""
        parts = self.args.db_fill.split(":")
        if len(parts) != 2:
            self.logger.fail("Invalid format. Use DB:BYTE (e.g., 1:00)")
            self.results["success"] = False
            return None
        db_num, fill_byte = int(parts[0]), int(parts[1], 16)
        self.logger.display(f"Filling DB{db_num} with 0x{fill_byte:02X}...")
        return self.scanner.db_fill(self.conn, db_num, fill_byte)

    def _action_set_datetime(self):
        """Handle --set-datetime action"""
        from datetime import datetime

        dt_str = self.args.set_datetime
        try:
            dt = datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            self.logger.fail("Invalid datetime format. Use: YYYY-MM-DD HH:MM:SS")
            self.results["success"] = False
            return None
        self.logger.display(f"Setting PLC datetime to {dt}...")
        return self.scanner.set_plc_datetime(self.conn, dt)

    def _action_read_szl(self):
        """Handle --read-szl-id action"""
        parts = self.args.read_szl_id.split(":")
        if len(parts) != 2:
            self.logger.fail("Invalid format. Use ID:INDEX (e.g., 0x0011:0)")
            self.results["success"] = False
            return None
        szl_id = int(parts[0], 16) if parts[0].startswith("0x") else int(parts[0])
        index = int(parts[1])
        self.logger.display(f"Reading SZL {hex(szl_id)}:{index}...")
        return self.scanner.read_szl(self.conn, szl_id, index)

    def _action_get_block_info(self):
        """Handle --get-block-info action"""
        parts = self.args.get_block_info.split(":")
        if len(parts) != 2:
            self.logger.fail("Invalid format. Use TYPE:NUM (e.g., DB:1)")
            self.results["success"] = False
            return None
        block_type, block_num = parts[0].upper(), int(parts[1])
        self.logger.display(f"Getting {block_type}{block_num} info...")
        return self.scanner.get_block_info(self.conn, block_type, block_num)

    def _action_monitor(self):
        """Handle --monitor action"""
        areas = self.args.monitor
        interval = getattr(self.args, "monitor_interval", 0.5)
        size = getattr(self.args, "monitor_size", 16)
        duration = getattr(self.args, "monitor_duration", 0)
        show_bits = getattr(self.args, "monitor_bits", False)
        return self.scanner.monitor(
            self.conn,
            areas=areas,
            interval=interval,
            size=size,
            duration=duration,
            show_bits=show_bits,
        )

    def _action_default_creds(self):
        """Handle --default-creds action (tests built-in default passwords)"""
        rate_limit = getattr(self.args, "brute_rate", 0.5)
        continue_on_success = getattr(self.args, "continue_on_success", False)
        result = self.scanner.bruteforce_password(
            self.conn, rate_limit=rate_limit, continue_on_success=continue_on_success
        )
        if result and result.get("success"):
            self.results["data"]["password_found"] = result.get("password")
        return result

    def _action_brute(self):
        """Handle --brute action"""
        wordlist = getattr(self.args, "wordlist", None)
        continue_on_success = getattr(self.args, "continue_on_success", False)
        rate_limit = getattr(self.args, "brute_rate", 0.5)
        result = self.scanner.bruteforce_password(
            self.conn,
            wordlist_path=wordlist,
            rate_limit=rate_limit,
            continue_on_success=continue_on_success,
        )
        if result and result.get("success"):
            self.results["data"]["password_found"] = result.get("password")
        return result

    def _parse_range(self, range_str: str) -> tuple:
        """Parse START:SIZE range string"""
        parts = range_str.split(":")
        if len(parts) != 2:
            raise ValueError(f"Invalid range format: {range_str}")
        return int(parts[0]), int(parts[1])

    def _handle_fuzz(self) -> None:
        """Handle fuzzing mode (--fuzz)"""
        mode = getattr(self.args, "fuzz", "db")
        if not mode:
            return

        # Safety check
        if not getattr(self.args, "confirm", False):
            self.logger.fail("--fuzz requires --confirm flag (DANGEROUS operation)")
            return

        iterations = getattr(self.args, "fuzz_iterations", 10)

        self.logger.display(f"Starting fuzz mode: {mode} ({iterations} iterations)")

        # Data block fuzzing
        if mode in ("db", "all"):
            self._fuzz_db(iterations)

        # Memory area fuzzing (markers, outputs)
        if mode in ("memory", "all"):
            self._fuzz_memory(iterations)

    def _fuzz_db(self, iterations: int) -> None:
        """Fuzz data block contents"""
        import time
        from ...utils.fuzzer import fuzz

        fuzz_db_arg = getattr(self.args, "fuzz_db", None)

        if fuzz_db_arg:
            try:
                parts = fuzz_db_arg.split(":")
                if len(parts) != 3:
                    self.logger.fail("Invalid --fuzz-db format. Use DB:START:SIZE")
                    return
                db_num, start, size = int(parts[0]), int(parts[1]), int(parts[2])
                targets = [(db_num, start, size)]
            except ValueError as e:
                self.logger.fail(f"Invalid --fuzz-db: {e}")
                return
        else:
            targets = self._find_accessible_dbs()
            if not targets:
                self.logger.warning("No accessible data blocks found for fuzzing")
                return

        self.logger.display(f"Fuzzing {len(targets)} data block target(s)")

        for db_num, start, size in targets:
            target_id = f"db{db_num}:{start}"

            def read_fn(db=db_num, s=start, sz=size):
                return bytes(self.conn.db_read(db, s, sz))

            def write_fn(data, db=db_num, s=start, sz=size):
                try:
                    write_data = data[:sz].ljust(sz, b"\x00")
                    self.conn.db_write(db, s, write_data)
                    return True
                except Exception as e:
                    self.logger.debug(f"db_write failed: {e}")
                    return False

            original = read_fn()
            successful, failed, anomalies, crashes = 0, 0, 0, 0

            for payload, _desc in fuzz(original, count=iterations):  # fuzz() yields (bytes, desc) tuples
                try:
                    if write_fn(payload):
                        successful += 1
                        readback = read_fn()
                        if readback != payload and readback != original:
                            anomalies += 1
                    else:
                        failed += 1
                except Exception:
                    crashes += 1
                time.sleep(0.1)

            if original:
                write_fn(original)

            status = "+" if crashes == 0 and anomalies == 0 else "!"
            self.logger.display(
                f"  [{status}] {target_id}: {successful + failed} tests, "
                f"{successful} writes, {anomalies} anomalies, {crashes} crashes"
            )

    def _find_accessible_dbs(self) -> List[tuple]:
        """Find accessible data blocks for fuzzing"""
        Block = _get_block_types()
        targets = []
        try:
            # Try to enumerate DBs
            max_targets = getattr(self.args, "fuzz_max_targets", 10)
            db_list = self.conn.list_blocks_of_type(Block.DB, 100)
            for db_num in db_list[:max_targets]:
                if db_num > 0:
                    try:
                        # Try to read first 10 bytes
                        self.conn.db_read(db_num, 0, 10)
                        targets.append((db_num, 0, 10))
                    except Exception as e:
                        self.logger.debug(f"DB{db_num} not accessible: {e}")
        except Exception as e:
            self.logger.debug(f"DB enumeration failed, trying common DBs: {e}")
            # Fallback: try common DBs
            for db_num in [1, 2, 10]:
                try:
                    self.conn.db_read(db_num, 0, 10)
                    targets.append((db_num, 0, 10))
                except Exception as e:
                    self.logger.debug(f"DB{db_num} not accessible: {e}")
        return targets

    def _fuzz_area(self, area, size: int, label: str, iterations: int) -> None:
        """Fuzz a single S7 memory area: read original, write mutations, restore."""
        import time
        from ...utils.fuzzer import fuzz

        try:
            self.conn.read_area(area, 0, 0, size)  # Test read

            def read_area():
                return bytes(self.conn.read_area(area, 0, 0, size))

            def write_area(data):
                try:
                    write_data = data[:size].ljust(size, b"\x00")
                    self.conn.write_area(area, 0, 0, bytearray(write_data))
                    return True
                except Exception as e:
                    self.logger.debug(f"write_area({label}) failed: {e}")
                    return False

            original = read_area()
            successful, failed, anomalies, crashes = 0, 0, 0, 0

            for payload, _desc in fuzz(original, count=iterations):  # fuzz() yields (bytes, desc)
                try:
                    if write_area(payload):
                        successful += 1
                        readback = read_area()
                        if readback != payload and readback != original:
                            anomalies += 1
                    else:
                        failed += 1
                except Exception:
                    crashes += 1
                time.sleep(0.1)

            if original:
                write_area(original)

            status = "+" if crashes == 0 and anomalies == 0 else "!"
            self.logger.display(
                f"  [{status}] {label}: {successful + failed} tests, "
                f"{successful} writes, {anomalies} anomalies, {crashes} crashes"
            )

        except Exception as e:
            self.logger.debug(f"{label} area not accessible: {e}")

    def _fuzz_memory(self, iterations: int) -> None:
        """Fuzz memory areas (markers, outputs)"""
        self.logger.display("Fuzzing memory areas (M, Q)...")
        self._fuzz_area(S7MemoryArea.MK, 10, "M:0-9", iterations)
        self._fuzz_area(S7MemoryArea.PA, 8, "Q:0-7", iterations)

    def cleanup(self):
        """Cleanup Snap7 connection"""
        from .scanner import _suppress_snap7_logging

        with _suppress_snap7_logging():
            if self.conn:
                try:
                    self.scanner.disconnect(self.conn)
                    self.logger.debug("Connection closed")
                except Exception as e:
                    self.logger.debug(f"Error closing connection: {e}")

    @staticmethod
    def check_dependencies() -> bool:
        from .scanner import _snap7

        return _snap7.is_available


# Module-level alias for loader discovery
# Maps protocol file name "snap7" to NXC-style class "s7"
snap7 = s7
