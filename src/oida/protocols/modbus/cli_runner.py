"""
Modbus NXC-style Connection

This module provides the NXC-style callable Modbus scanner class that wraps
ModbusScanner to provide automatic execution on instantiation.

The class uses mixins for feature-specific handler methods:
    - IdentificationMixin: MEI device ID, Server ID, Exception Status
    - DiagnosticsMixin: FC 8 diagnostics
    - EventsMixin: Communication events (FC 11, 12)
    - FilesMixin: File record operations (FC 20, 21, 22, 23, 24)
    - WritesMixin: Write operations (FC 5, 6, 15, 16)
    - MonitorMixin: Register monitoring mode
    - FuzzMixin: Security fuzzing
    - CANopenMixin: CANopen MEI operations (FC 43/13)
    - RawFCMixin: Custom function code handling
    - SunSpecMixin: SunSpec runtime model discovery
"""

from typing import Any

from ...connection import NetworkConnection
from ...utils.exceptions import DependencyError
from ...utils.lazy_import import lazy_import

_pymodbus = lazy_import("pymodbus", "Modbus")

from .constants import (
    EXCEPTION_CODES,
)
from .decoder import (
    ModbusDecoder,
    REGISTERS_PER_TYPE,
)
from .mixins import (
    IdentificationMixin,
    DiagnosticsMixin,
    EventsMixin,
    FilesMixin,
    WritesMixin,
    MonitorMixin,
    FuzzMixin,
    CANopenMixin,
    RawFCMixin,
    SunSpecMixin,
    MapReadWriteMixin,
)


class modbus(
    IdentificationMixin,
    DiagnosticsMixin,
    EventsMixin,
    FilesMixin,
    WritesMixin,
    MonitorMixin,
    FuzzMixin,
    CANopenMixin,
    RawFCMixin,
    SunSpecMixin,
    MapReadWriteMixin,
    NetworkConnection,
):
    """
    NXC-style Modbus scanner (callable)

    This class wraps the existing ModbusScanner to provide NXC-style
    callable behavior while maintaining all existing functionality.

    Usage:
        args = argparse.Namespace(...)
        scanner = modbus(args, None, '192.168.1.100')
        # Scan automatically executes via proto_flow()
    """

    def __init__(self, args: Any, db, host):
        """
        Initialize and trigger Modbus scan

        Args:
            args: Command-line arguments
            db: Database instance (optional, not used yet)
            host: Target IP address
        """
        self.protocol_name = "Modbus"
        self.default_port = 502

        # Extract decode/encode settings from args for typed operations
        self.decode_type = getattr(args, "decode", None) or getattr(args, "d", None)
        self.endian = getattr(args, "endian", "big")

        # Initialize base class (triggers proto_flow)
        super().__init__(args, db, host)

    @property
    def broadcast_mode(self) -> bool:
        """Check if broadcast mode is enabled (unit ID 0, write-only, no response)"""
        return getattr(self.args, "broadcast", False)

    def _handle_list_maps(self):
        """List available register maps and exit"""
        from .decoder import list_register_maps
        from ...utils.export_utils import print_table

        maps = list_register_maps()

        # Build table rows sorted by name
        rows = []
        for m in sorted(maps, key=lambda x: x["name"].lower()):
            name = m.get("name", "")
            vendor = m.get("vendor", "Unknown")
            model = m.get("model", "")
            category = m.get("category", "")
            rows.append([name, vendor, model, category])

        headers = ["Name", "Vendor", "Model", "Category"]
        print_table(
            rows,
            headers,
            title=f"Register Maps ({len(maps)} total)",
            logger=self.logger,
        )

        self.logger.display("")
        self.logger.display("Usage: oida modbus <target> --register-map <name>")

    def proto_flow(self):
        """
        Main Modbus scanning workflow (NXC-style)

        Orchestrates the scanning process with support for all features:
        - Device identification (MEI)
        - Register scanning with decoding
        - Diagnostics (FC 8)
        - Communication events (FC 11/12)
        - File records (FC 20)
        - FIFO queue (FC 24)
        - Fingerprinting
        - Monitoring mode
        - Write operations
        """
        # Import scanner here to avoid circular imports
        from .scanner import ModbusScanner

        # Setup logging
        self.logger.debug(
            f"Starting Modbus workflow for {self.ip}:{getattr(self.args, 'port', 502)}"
        )

        # Handle --list-maps without connection
        if getattr(self.args, "list_maps", False):
            self.logger.debug("Listing register maps (no connection)")
            self._handle_list_maps()
            return

        # Convert args to dict format expected by ModbusScanner
        args_dict = self._convert_args_to_dict()
        self.logger.debug(
            f"Scanner options: unit_id={args_dict.get('unit_id', 1)}, "
            f"timeout={args_dict.get('timeout', 5)}"
        )

        # Create ModbusScanner instance
        self.scanner = ModbusScanner(args_dict)

        # Create connection via scanner
        self.logger.debug("Creating connection...")
        self.create_conn_obj()

        if not self.conn:
            self.logger.fail(f"Failed to connect to {self.ip}:{getattr(self.args, 'port', 502)}")
            self.results["success"] = False
            self.results["error"] = (
                f"Connection failed to {self.ip}:{getattr(self.args, 'port', 502)}"
            )
            return

        self.logger.debug("Connection established")

        # Enumerate device information
        self.logger.debug("Enumerating device information...")
        self.enum_host_info()

        # Print host information
        self.print_host_info()

        # Execute features based on arguments
        self.logger.debug("Executing requested features...")
        self._execute_features()

        self.logger.debug("Modbus workflow complete")

    def _execute_features(self):
        """Execute features based on command-line arguments"""
        if not self.conn:
            return

        # Workflow shortcut modes
        full_mode = getattr(self.args, "full", False)
        discover_mode = getattr(self.args, "discover", False)

        # Log broadcast mode status if enabled
        if self.broadcast_mode:
            # --broadcast is a Modbus-RTU-only concept (Unit ID 0 = no
            # response expected from any slave on the serial bus). It
            # has no meaning on Modbus/TCP, /TLS, or /UDP — pymodbus
            # will happily send the frame but every server will either
            # ignore it or send an exception, neither of which the
            # caller treats as 'broadcast'. Refuse explicitly on
            # non-RTU transports.
            on_serial = bool(
                getattr(self.args, "serial_port", None)
                or getattr(self.args, "rtu_over_tcp", False)
                or getattr(self.args, "ascii_over_tcp", False)
            )
            if not on_serial:
                self.logger.fail(
                    "--broadcast is Modbus-RTU only (Unit ID 0, no response). "
                    "Use --serial-port, --rtu-over-tcp, or --ascii-over-tcp."
                )
                return
            self.logger.warning(
                "[Broadcast Mode] Unit ID 0 - writes sent to ALL slaves, NO response expected"
            )
            self.logger.display(
                "    Only write operations (FC 5, 6, 15, 16) are meaningful in broadcast mode"
            )
            # Override unit_id to 0 for broadcast
            setattr(self.args, "unit_id", 0)

        # --discover: Quick recon (identify only)
        if discover_mode:
            return  # Just show connection info

        # Device identification (-i/--identify) - read MEI device info
        if getattr(self.args, "identify", False) or full_mode:
            self._handle_identify()

        # Server ID (--server-id)
        if getattr(self.args, "server_id", False):
            self._handle_server_id()

        # Exception Status (--exception-status)
        if getattr(self.args, "exception_status", False):
            self._handle_exception_status()

        # Diagnostics (--diag)
        diag_tests = getattr(self.args, "diag", None)
        if diag_tests:
            self._handle_diagnostics(diag_tests)

        # Communication events (--events or --event-count-only)
        if getattr(self.args, "events", False) or getattr(self.args, "event_count_only", False):
            self._handle_events()

        # Unit ID discovery (--discover-units)
        if getattr(self.args, "discover_units", False):
            self._handle_discover_units()

        # --sunspec-assess implies --sunspec
        if getattr(self.args, "sunspec_assess", False):
            setattr(self.args, "sunspec", True)

        # SunSpec discovery (--sunspec)
        if getattr(self.args, "sunspec", False) or full_mode:
            self._handle_sunspec()

        # File record read (--file-read)
        file_spec = getattr(self.args, "file_read", None)
        if file_spec:
            self._handle_file_read(file_spec)

        # File record write (--file-write) - FC 21
        file_write_spec = getattr(self.args, "file_write", None)
        if file_write_spec:
            self._handle_file_write(file_write_spec)

        # Mask write register (--mask-write) - FC 22
        mask_write_spec = getattr(self.args, "mask_write", None)
        if mask_write_spec:
            self._handle_mask_write(mask_write_spec)

        # Atomic read/write (--atomic-rw) - FC 23
        atomic_rw_spec = getattr(self.args, "atomic_rw", None)
        if atomic_rw_spec:
            self._handle_atomic_rw(atomic_rw_spec)

        # FIFO queue (--fifo)
        fifo_addr = getattr(self.args, "fifo", None)
        if fifo_addr is not None:
            self._handle_fifo(fifo_addr)

        # Register scanning (default or with scan-range)
        # Skip scan if monitor-only, fuzz, or write operations are requested
        monitor_only = getattr(self.args, "monitor", False) and not any(
            getattr(self.args, a, None) for a in ["identify", "diag", "full"]
        )
        fuzz_or_write = getattr(self.args, "fuzz", False) or any(
            getattr(self.args, a, None)
            for a in ["write", "write_coil", "write_multiple", "write_multiple_coils"]
        )
        scan_range = getattr(self.args, "scan_range", None)
        register_map_name = getattr(self.args, "register_map", None)
        fc_scan = getattr(self.args, "fc_all", False) or getattr(self.args, "scan_fc", False)
        self.logger.debug(
            f"fc_scan={fc_scan}, scan_range={scan_range}, monitor_only={monitor_only}, fuzz_or_write={fuzz_or_write}"
        )

        # Map-based name operations (--list-names, --search-name, --read-name, --write-name)
        if getattr(self.args, "list_names", False):
            self._handle_list_names()
        if getattr(self.args, "search_name", None):
            self._handle_search_name()
        if getattr(self.args, "read_name", None):
            self._handle_read_name()
        if getattr(self.args, "write_name", None):
            self._handle_write_name()

        # If register-map specified without scan_range, read registers from map
        if register_map_name and not scan_range and not fuzz_or_write and not monitor_only:
            self._read_registers_from_map(register_map_name)
        elif (
            not monitor_only
            and not fuzz_or_write
            and (scan_range or fc_scan)  # Scan if range or FC scan requested
        ):
            self._execute_scan()

        # Write operation (-w/--write single register)
        write_spec = getattr(self.args, "write", None)
        if write_spec:
            self._handle_write()

        # Write coil (--write-coil)
        write_coil_spec = getattr(self.args, "write_coil", None)
        if write_coil_spec:
            self._handle_write_coil()

        # Write multiple registers (--write-multiple)
        write_multiple_spec = getattr(self.args, "write_multiple", None)
        if write_multiple_spec:
            self._handle_write_multiple()

        # Write multiple coils (--write-multiple-coils)
        write_coils_spec = getattr(self.args, "write_multiple_coils", None)
        if write_coils_spec:
            self._handle_write_multiple_coils()

        # Test write access (--test-write or --test-write-thorough)
        if getattr(self.args, "test_write", False) or getattr(
            self.args, "test_write_thorough", False
        ):
            self._handle_test_write()

        # Enumerate function codes (--enumerate-functions)
        if getattr(self.args, "enumerate_functions", False):
            self._handle_enumerate_functions()

        # Custom function code (--raw-fc)
        if getattr(self.args, "raw_fc", None) is not None:
            self._handle_raw_fc()

        # CANopen MEI (FC 43/13) operations
        if getattr(self.args, "canopen_info", False):
            self._handle_canopen_info()
        if getattr(self.args, "canopen_read", None):
            self._handle_canopen_read()
        if getattr(self.args, "canopen_write", None):
            if not getattr(self.args, "confirm", False):
                self.logger.fail("CANopen write requires --confirm flag")
            else:
                self._handle_canopen_write()

        # Monitoring mode (--monitor) - runs last as it's blocking
        if getattr(self.args, "monitor", False):
            self._handle_monitor()

        # Fuzzing mode (--fuzz) - requires --confirm
        if getattr(self.args, "fuzz", None):
            self._handle_fuzz()

    def _handle_discover_units(self):
        """Handle unit ID discovery (--discover-units)"""
        unit_range = getattr(self.args, "unit_range", "1-247")
        self.logger.display(f"[Unit ID Discovery] Scanning ({unit_range})...")

        units = self.scanner._discover_units(self.conn)
        self.results["data"]["units"] = units

        if units:
            # Check for gateway mode detection
            if units.get("gateway_mode"):
                self.logger.warning("Gateway/Bridge mode detected")
                if "actual_unit" in units:
                    self.logger.display(
                        f"      Device responds to all unit IDs (actual: {units['actual_unit']})"
                    )
                if "responding_units" in units:
                    self.logger.display(f"      Tested units: {units['responding_units']}")
                if "error_code" in units:
                    self.logger.display(f"      Error code: {units['error_code']}")
                if "note" in units:
                    self.logger.display(f"      {units['note']}")
            else:
                # Normal mode - show all discovered units
                active_units = [k for k in units.keys() if isinstance(k, int)]
                if active_units:
                    self.logger.display(f"  Found {len(active_units)} active unit(s)")
                    if len(active_units) <= 10:
                        for uid in sorted(active_units):
                            self.logger.display(f"    Unit {uid}")
                    else:
                        # Compact display for many units
                        unit_list = sorted(active_units)
                        self.logger.display(
                            f"    Units: {', '.join(map(str, unit_list[:20]))}"
                            + (f"... (+{len(unit_list) - 20} more)" if len(unit_list) > 20 else "")
                        )

                    # High response count warning
                    if units.get("high_response_count"):
                        self.logger.warning(
                            units.get("high_response_warning", "High response count")
                        )
                        self.logger.display(
                            "      Consider using --unit-id to specify the actual slave address"
                        )
                else:
                    self.logger.display("  No active units found")
        else:
            self.logger.display("  No active units found")

    def _read_registers_from_map(self, map_name: str):
        """Read and display all registers defined in a register map."""
        from .decoder import load_register_map

        # Load the register map
        reg_map = load_register_map(map_name)
        if not reg_map:
            self.logger.fail(f"Register map not found: {map_name}")
            return

        vendor = reg_map.get("vendor", "Unknown")
        model = reg_map.get("model", "Unknown")
        description = reg_map.get("description", "")
        byte_order = reg_map.get("byte_order", "big")
        word_order = reg_map.get("word_order", "big")
        standard = reg_map.get("standard")

        self.logger.display(f"[Register Map] {vendor} {model}")
        if description:
            self.logger.display(f"  {description}")
        if standard:
            self.logger.display(f"  Standard: {standard.upper()}")
        self.logger.display(f"  Byte order: {byte_order}, Word order: {word_order}")

        # Use map's default unit ID only if the user did not explicitly pass --unit-id
        # (argparse default is None). An explicit --unit-id 1 must be honored verbatim.
        user_unit_id = getattr(self.args, "unit_id", None)
        default_uid = reg_map.get("default_unit_id")
        if user_unit_id is None:
            if default_uid is not None:
                unit_id = default_uid
                self.logger.display(f"  Using default unit ID from map: {default_uid}")
            else:
                unit_id = 1
        else:
            unit_id = user_unit_id

        registers_def = reg_map.get("registers", {})
        if not registers_def:
            self.logger.warning("No registers defined in map")
            return

        # Group registers by function code / register type
        holding_regs = {}  # FC 3
        input_regs = {}  # FC 4

        for name, reg_def in registers_def.items():
            address = reg_def.get("address")
            if address is None or not isinstance(address, int):
                continue

            fc = reg_def.get("function_code", 3)
            if fc == 4:
                input_regs[name] = reg_def
            else:
                holding_regs[name] = reg_def

        # Track summary stats
        total_ok = 0
        total_errors = 0
        summary_parts = []

        # Read and display holding registers (FC 3)
        if holding_regs:
            stats = self._read_and_display_map_registers(
                holding_regs,
                "holding",
                unit_id,
                byte_order,
                word_order,
                title="Holding Registers (FC 3)",
            )
            total_ok += stats["ok"]
            total_errors += stats["errors"]
            summary_parts.append(f"{stats['ok']} holding")

        # Read and display input registers (FC 4)
        if input_regs:
            stats = self._read_and_display_map_registers(
                input_regs,
                "input",
                unit_id,
                byte_order,
                word_order,
                title="Input Registers (FC 4)",
            )
            total_ok += stats["ok"]
            total_errors += stats["errors"]
            summary_parts.append(f"{stats['ok']} input")

        # Read coils if defined
        coils_def = reg_map.get("coils", {})
        if coils_def:
            stats = self._read_and_display_map_coils(coils_def, unit_id, title="Coils (FC 1)")
            total_ok += stats["ok"]
            total_errors += stats["errors"]
            summary_parts.append(f"{stats['ok']} coils")

        # Read discrete inputs if defined
        discrete_def = reg_map.get("discrete_inputs", {})
        if discrete_def:
            stats = self._read_and_display_map_discrete(
                discrete_def, unit_id, title="Discrete Inputs (FC 2)"
            )
            total_ok += stats["ok"]
            total_errors += stats["errors"]
            summary_parts.append(f"{stats['ok']} discrete")

        # Display summary
        summary = ", ".join(summary_parts)
        self.logger.display(f"[Summary] {total_ok} OK, {total_errors} errors ({summary})")

    def _read_and_display_map_registers(
        self,
        registers_def: dict,
        reg_type: str,
        unit_id: int,
        byte_order: str,
        word_order: str,
        title: str = None,
    ) -> dict:
        """Read and display registers from map definition.

        # TODO: batch when register_io supports variable-width reads
        # (each register may need 1-N words depending on dtype: u16=1, u32=2, string=N)
        """
        from ...utils.export_utils import print_table

        decoder = ModbusDecoder(byte_order=byte_order, word_order=word_order)
        verbose = getattr(self.args, "verbose", 0) or 0

        # Sort by address
        sorted_regs = sorted(registers_def.items(), key=lambda x: x[1].get("address", 0))

        stats = {"ok": 0, "errors": 0}
        rows = []

        # Headers depend on verbose mode
        if verbose:
            headers = ["Name", "Addr", "Type", "Acc", "Value", "Raw", "Description"]
        else:
            headers = ["Name", "Addr", "Type", "Acc", "Value", "Description"]

        # First pass: read every register and collect all raw word values so that
        # scale_factor_register lookups resolve regardless of whether the SF
        # register precedes or follows its value register in address order.
        all_registers = {}
        read_results = {}  # name -> (raw_regs, raw_hex) or None on read error

        for name, reg_def in sorted_regs:
            address = reg_def.get("address")
            dtype = reg_def.get("type", "u16")
            description = reg_def.get("description", "")

            # Determine register count (handle strings with length field)
            if dtype in ("str", "string"):
                char_length = reg_def.get("length", 2)
                regs_needed = (char_length + 1) // 2
            else:
                regs_needed = REGISTERS_PER_TYPE.get(dtype, 1) or 1

            try:
                if reg_type == "input":
                    result = self.conn.read_input_registers(
                        address, count=regs_needed, device_id=unit_id
                    )
                else:
                    result = self.conn.read_holding_registers(
                        address, count=regs_needed, device_id=unit_id
                    )

                if result.isError():
                    read_results[name] = ("error", result)
                    continue

                raw_regs = list(result.registers)
                raw_hex = " ".join(f"{r:04X}" for r in raw_regs)

                # Store register values for scale_factor_register lookups
                for i, reg_val in enumerate(raw_regs):
                    all_registers[address + i] = reg_val

                read_results[name] = (raw_regs, raw_hex)

            except Exception as e:
                read_results[name] = ("exception", e)

        # Second pass: decode/display using the fully populated all_registers map.
        for name, reg_def in sorted_regs:
            address = reg_def.get("address")
            dtype = reg_def.get("type", "u16")
            enum_map = reg_def.get("enum")
            scale_factor_reg = reg_def.get("scale_factor_register")
            access = reg_def.get("access", "r")
            unit = reg_def.get("unit", "")
            scale = reg_def.get("scale", 1.0)
            offset = reg_def.get("offset", 0.0)
            description = reg_def.get("description", "")
            hex_addr = reg_def.get("hex_address", f"0x{address:04X}")

            outcome = read_results.get(name)

            if outcome is not None and outcome[0] == "exception":
                e = outcome[1]
                stats["errors"] += 1
                if verbose:
                    rows.append([name, hex_addr, dtype, access, f"ERROR: {e}", "-", description])
                else:
                    rows.append([name, hex_addr, dtype, access, f"ERROR: {e}", description])
                continue

            if outcome is not None and outcome[0] == "error":
                result = outcome[1]
                stats["errors"] += 1
                exc_code = getattr(result, "exception_code", None)
                if exc_code is not None:
                    exc_name = EXCEPTION_CODES.get(exc_code, f"Unknown ({exc_code})")
                    value_str = f"ERR:{exc_code:02d}"
                    err_desc = f"{exc_name} - {description}" if description else exc_name
                else:
                    value_str = "ERROR"
                    err_desc = description
                if verbose:
                    rows.append([name, hex_addr, dtype, access, value_str, "-", err_desc])
                else:
                    rows.append([name, hex_addr, dtype, access, value_str, err_desc])
                continue

            try:
                raw_regs, raw_hex = outcome

                # Decode the value
                decoded = decoder.decode(raw_regs, dtype)
                if decoded and decoded[0].get("value") is not None:
                    raw_value = decoded[0]["value"]
                    # Apply scale and offset (or dynamic scale factor)
                    if isinstance(raw_value, (int, float)):
                        if scale_factor_reg is not None and scale_factor_reg in all_registers:
                            sf_value = all_registers[scale_factor_reg]
                            if sf_value > 32767:
                                sf_value -= 65536
                            dynamic_scale = 10**sf_value
                            value = raw_value * dynamic_scale
                        else:
                            value = raw_value * scale + offset
                        if isinstance(value, float) and value.is_integer():
                            value_str = f"{int(value)}"
                        elif isinstance(value, float):
                            value_str = f"{value:.6g}"
                        else:
                            value_str = f"{value}"
                        if enum_map:
                            key = str(int(value))
                            enum_label = enum_map.get(key)
                            if enum_label:
                                value_str = f"{value_str} ({enum_label})"
                        if unit:
                            value_str = f"{value_str} {unit}"
                    elif isinstance(raw_value, str):
                        value_str = raw_value if raw_value else "(empty)"
                    else:
                        value_str = f"{raw_value}" if raw_value else "(empty)"
                    stats["ok"] += 1
                else:
                    value_str = f"[{raw_hex}]"
                    stats["ok"] += 1

                if verbose:
                    rows.append([name, hex_addr, dtype, access, value_str, raw_hex, description])
                else:
                    rows.append([name, hex_addr, dtype, access, value_str, description])

            except Exception as e:
                stats["errors"] += 1
                if verbose:
                    rows.append([name, hex_addr, dtype, access, f"ERROR: {e}", "-", description])
                else:
                    rows.append([name, hex_addr, dtype, access, f"ERROR: {e}", description])

        if rows:
            print_table(rows, headers, title=title, logger=self.logger)

        return stats

    def _read_and_display_map_coils(self, coils_def: dict, unit_id: int, title: str = None) -> dict:
        """Read and display coils from map definition."""
        return self._read_and_display_map_bits(
            coils_def,
            unit_id,
            bit_type="coil",
            batch_type="coils",
            read_func=self.conn.read_coils,
            default_access="rw",
            title=title,
        )

    def _read_and_display_map_discrete(
        self, discrete_def: dict, unit_id: int, title: str = None
    ) -> dict:
        """Read and display discrete inputs from map definition."""
        return self._read_and_display_map_bits(
            discrete_def,
            unit_id,
            bit_type="discrete",
            batch_type="discrete_inputs",
            read_func=self.conn.read_discrete_inputs,
            default_access="r",
            title=title,
        )

    def _read_and_display_map_bits(
        self,
        bits_def: dict,
        unit_id: int,
        bit_type: str,
        batch_type: str,
        read_func,
        default_access: str,
        title: str = None,
    ) -> dict:
        """Read and display coils or discrete inputs from map definition.

        Args:
            bits_def: Register map definitions for the bit-type registers.
            unit_id: Modbus slave/unit ID.
            bit_type: Display label ("coil" or "discrete").
            batch_type: Key for read_registers_batched ("coils" or "discrete_inputs").
            read_func: Individual read callable (e.g. conn.read_coils).
            default_access: Default access mode when not specified in the map.
            title: Optional table title.
        """
        from ...utils.export_utils import print_table
        from .register_io import read_registers_batched

        sorted_items = sorted(bits_def.items(), key=lambda x: x[1].get("address", 0))
        verbose = getattr(self.args, "verbose", 0) or 0

        stats = {"ok": 0, "errors": 0}
        rows: list = []

        if verbose:
            headers = ["Name", "Addr", "Type", "Acc", "Value", "Raw", "Description"]
        else:
            headers = ["Name", "Addr", "Type", "Acc", "Value", "Description"]

        # Batch-read all addresses.
        all_addrs = sorted(
            {d.get("address") for d in bits_def.values() if d.get("address") is not None}
        )
        batch_values = read_registers_batched(
            self.conn, batch_type, all_addrs, unit_id=unit_id, fallback_individual=False
        )

        for name, item_def in sorted_items:
            address = item_def.get("address")
            access = item_def.get("access", default_access)
            description = item_def.get("description", "")
            hex_addr = item_def.get("hex_address", f"0x{address:04X}")

            if address in batch_values:
                value = batch_values[address]
                value_str = "ON" if value else "OFF"
                raw_hex = "01" if value else "00"
                stats["ok"] += 1

                if verbose:
                    rows.append([name, hex_addr, bit_type, access, value_str, raw_hex, description])
                else:
                    rows.append([name, hex_addr, bit_type, access, value_str, description])
            else:
                # Batch missed this address -- try individual read for exception code info.
                try:
                    result = read_func(address, count=1, device_id=unit_id)
                    if result.isError():
                        stats["errors"] += 1
                        exc_code = getattr(result, "exception_code", None)
                        if exc_code is not None:
                            exc_name = EXCEPTION_CODES.get(exc_code, f"Unknown ({exc_code})")
                            value_str = f"ERR:{exc_code:02d}"
                            err_desc = f"{exc_name} - {description}" if description else exc_name
                        else:
                            value_str = "ERROR"
                            err_desc = description
                        if verbose:
                            rows.append(
                                [name, hex_addr, bit_type, access, value_str, "-", err_desc]
                            )
                        else:
                            rows.append([name, hex_addr, bit_type, access, value_str, err_desc])
                    else:
                        value = result.bits[0]
                        value_str = "ON" if value else "OFF"
                        raw_hex = "01" if value else "00"
                        stats["ok"] += 1
                        if verbose:
                            rows.append(
                                [name, hex_addr, bit_type, access, value_str, raw_hex, description]
                            )
                        else:
                            rows.append([name, hex_addr, bit_type, access, value_str, description])
                except Exception as e:
                    stats["errors"] += 1
                    if verbose:
                        rows.append(
                            [name, hex_addr, bit_type, access, f"ERROR: {e}", "-", description]
                        )
                    else:
                        rows.append([name, hex_addr, bit_type, access, f"ERROR: {e}", description])

        if rows:
            print_table(rows, headers, title=title, logger=self.logger)

        return stats

    def create_conn_obj(self):
        """Create Modbus connection object"""
        if not _pymodbus.is_available:
            raise DependencyError(
                "pymodbus library required for Modbus protocol.\n"
                "Install with: pip install oida-ics[modbus]",
                protocol="Modbus",
            )

        # Determine transport type
        if getattr(self.args, "tls", False):
            transport = "TLS"
        elif getattr(self.args, "udp", False):
            transport = "UDP"
        elif getattr(self.args, "rtu_over_tcp", False):
            transport = "RTU-over-TCP"
        elif getattr(self.args, "ascii_over_tcp", False):
            transport = "ASCII-over-TCP"
        elif getattr(self.args, "serial_port", None):
            transport = "RTU"
        else:
            transport = "TCP"

        self.logger.info(f"Connecting to {self.ip}:{getattr(self.args, 'port', 502)}")

        # Use scanner's connect method
        self.conn = self.scanner.connect()

        if self.conn:
            self.logger.success(f"Connected via {transport}")
        else:
            self.logger.fail("Connection failed")

    def enum_host_info(self):
        """Enumerate Modbus device information"""
        if not self.conn:
            return

        # Modbus/TCP is plaintext by design (no TLS in the protocol). We are
        # on a confirmed-live connection here, so emit the no-encryption finding.
        self.logger.security_finding(
            "No encryption",
            detail="Modbus/TCP has no transport encryption (cleartext)",
        )

        # Get server info via scanner (scanner logs details)
        server_info = self.scanner._get_server_info(self.conn)

        self.results["data"]["server_info"] = server_info
        self.results["data"]["connection_type"] = server_info.get("connection_type", "TCP")

    def print_host_info(self):
        """Display discovered Modbus device information"""
        server_info = self.results["data"].get("server_info", {})

        if hasattr(self.args, "quiet") and self.args.quiet:
            return

        # Show unit ID being used
        unit_id = getattr(self.args, "unit_id", None)
        if unit_id is None:
            unit_id = 1
        if self.broadcast_mode:
            self.logger.display("    Unit ID: 0 (broadcast)")
        else:
            self.logger.display(f"    Unit ID: {unit_id}")

        if "server_id" in server_info:
            sid = server_info["server_id"]
            if isinstance(sid, dict):
                identifier = sid.get("identifier", "")
                sid_hex = sid.get("server_id_hex", "N/A")
                run_status = sid.get("run_status", "")

                if identifier:
                    display = f"    Server ID: {identifier}"
                else:
                    display = f"    Server ID: {sid_hex}"

                if run_status:
                    display += f" ({run_status})"
                self.logger.display(display)
            else:
                self.logger.display(f"    Server ID: {sid}")

        # Display MEI Device Identification if available
        if "device_identification" in server_info:
            device_id = server_info["device_identification"]
            self.logger.display("    [MEI Device Identification]")
            if "VendorName" in device_id:
                self.logger.display(f"      Vendor: {device_id['VendorName']}")
            if "ProductName" in device_id:
                self.logger.display(f"      Product: {device_id['ProductName']}")
            if "ProductCode" in device_id:
                self.logger.display(f"      Product Code: {device_id['ProductCode']}")
            if "MajorMinorRevision" in device_id:
                self.logger.display(f"      Version: {device_id['MajorMinorRevision']}")
            if "ModelName" in device_id:
                self.logger.display(f"      Model: {device_id['ModelName']}")
            if "VendorUrl" in device_id:
                self.logger.display(f"      URL: {device_id['VendorUrl']}")
            if "UserApplicationName" in device_id:
                self.logger.display(f"      Application: {device_id['UserApplicationName']}")
        elif "vendor" in server_info:
            self.logger.display(f"    Vendor: {server_info.get('vendor', 'Unknown')}")
            self.logger.display(f"    Product: {server_info.get('product', 'Unknown')}")
            self.logger.display(f"    Version: {server_info.get('version', 'Unknown')}")

    def _execute_scan(self):
        """Execute the main Modbus scanning logic"""
        if not self.conn:
            return

        self.logger.debug("Executing Modbus scan...")

        # Run discovery via scanner
        scan_results = self.scanner.discover(self.conn)

        # Store results
        self.results["data"]["scan_results"] = scan_results

    def cleanup(self):
        """Cleanup Modbus connection"""
        if self.conn:
            try:
                self.scanner.disconnect(self.conn)
                self.logger.debug("Modbus connection closed")
            except Exception as e:
                self.logger.debug(f"Error closing connection: {e}")
            finally:
                self.conn = None  # Prevent duplicate cleanup

    @staticmethod
    def check_dependencies() -> bool:
        """Check if Modbus dependencies are available"""
        return _pymodbus.is_available
