#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import struct
import time
import threading
from typing import Dict, List, Any, Optional
from datetime import datetime
from ...utils import (
    register_protocol,
    create_protocol_module,
    SerialScanner,
    parse_bool,
    ProtocolParser,
)
from ...utils.permissions import check_raw_socket_capability
from ...utils.cli import run as cli_run
from ...utils.lazy_import import lazy_import

# Import from submodules
from .constants import (
    lookup_vendor,
    get_slave_state_name,
    get_al_status_error,
)

# Import mixin classes
from .eeprom_ops import EepromOpsMixin
from .coe_ops import CoeOpsMixin
from .advanced_ops import AdvancedOpsMixin
from .fuzzing_ops import FuzzingOpsMixin
from .reporting import ReportingMixin

# Lazy imports - only load when actually used
_pysoem = lazy_import("pysoem", "EtherCAT")

# Module-level exports for test compatibility
pysoem = None


def _get_pysoem():
    """Get pysoem module, raising DependencyError if not available."""
    return _pysoem()


protocol_options = {
    "dump": {
        "type": "string",
        "description": "Directory path to dump EEPROM and SDO data",
        "required": False,
        "default": "",
    },
    "fuzz": {
        "type": "string",
        "description": "Fuzz testing mode: sdo, pdo, or all (WARNING: May cause device malfunction)",
        "required": False,
        "default": None,
    },
    "fuzz-iterations": {
        "type": "int",
        "description": "Fuzz iterations per target",
        "required": False,
        "default": 10,
    },
    "sdo": {
        "type": "bool",
        "description": "Read SDO information from devices",
        "required": False,
        "default": True,
    },
    "eeprom": {
        "type": "bool",
        "description": "Read EEPROM information from devices",
        "required": False,
        "default": True,
    },
    "scan-range": {
        "type": "string",
        "description": "Range of slave positions to scan",
        "required": False,
        "default": "1-16",
    },
    # New pysoem 1.1.x features
    "foe-read": {
        "type": "string",
        "description": "Read file from slave via FoE (format: slave_pos:filename)",
        "required": False,
        "default": "",
    },
    "foe-write": {
        "type": "string",
        "description": "Write file to slave via FoE (format: slave_pos:local_path)",
        "required": False,
        "default": "",
    },
    "dc-analysis": {
        "type": "bool",
        "description": "Analyze Distributed Clock synchronization",
        "required": False,
        "default": False,
    },
    "emergency-monitor": {
        "type": "bool",
        "description": "Monitor emergency messages from slaves",
        "required": False,
        "default": True,
    },
    "eeprom-dump": {
        "type": "bool",
        "description": "Dump full EEPROM contents (0x00-0x7F)",
        "required": False,
        "default": False,
    },
}


@register_protocol(
    name="EtherCAT Scanner",
    description="""EtherCAT industrial Ethernet protocol scanner""",
    authors=["f0rw4rd"],
    references=[{"type": "url", "ref": "https://www.ethercat.org"}],
    protocol_options=protocol_options,
    protocol_type="serial",
)
class EtherCATScanner(
    EepromOpsMixin,
    CoeOpsMixin,
    AdvancedOpsMixin,
    FuzzingOpsMixin,
    ReportingMixin,
    SerialScanner,
):
    """EtherCAT Scanner implementing the base scanner interface"""

    def __init__(self, args: Dict[str, Any]):
        # Set interface before super().__init__ since SerialScanner requires it
        args.setdefault("interface", args.get("target", "eth0"))
        # EtherCAT default timeout is 5s (bus protocol needs more time than TCP)
        args.setdefault("timeout", 5)
        super().__init__(args)

        self.dump_path = args.get("dump", "")
        fuzz_mode = args.get("fuzz", None)
        self.fuzz_sdo = fuzz_mode in ("sdo", "all")
        self.fuzz_pdo = fuzz_mode in ("pdo", "all")
        self.fuzz_iterations = int(args.get("fuzz_iterations", args.get("fuzz-iterations", 10)))
        self.read_sdo = parse_bool(args.get("sdo", True))
        self.read_eeprom = parse_bool(args.get("eeprom", True))
        self.scan_range = args.get("scan-range", "1-16")
        self.slave_positions = ProtocolParser.parse_address_range(self.scan_range)

        # Shared slave selection (-S / --slave)
        slave_val = args.get("slave", None)
        self.slave = int(slave_val) if slave_val is not None else None

        # New pysoem 1.1.x features
        self.foe_read = args.get("foe-read", args.get("foe_read", ""))
        self.foe_write = args.get("foe-write", args.get("foe_write", ""))
        self.dc_analysis = parse_bool(args.get("dc-analysis", args.get("dc_analysis", False)))
        self.emergency_monitor = parse_bool(
            args.get("emergency-monitor", args.get("emergency_monitor", True))
        )
        self.op_state = parse_bool(args.get("op-state", args.get("op_state", False)))
        self.boot_state = parse_bool(args.get("boot-state", args.get("boot_state", False)))
        self.esc_debug = parse_bool(args.get("esc-debug", args.get("esc_debug", False)))

        # Feature flags (now simple booleans, slave selection via shared -S)
        self.device_info = parse_bool(args.get("device-info", args.get("device_info", False)))
        self.sdo_scan = parse_bool(args.get("sdo_scan", args.get("sdo-scan", False)))
        self.eeprom_dump = parse_bool(args.get("eeprom-dump", args.get("eeprom_dump", False)))
        self.eeprom_parse = parse_bool(args.get("eeprom-parse", args.get("eeprom_parse", False)))
        self.scan_fsoe = parse_bool(args.get("scan-fsoe", args.get("scan_fsoe", False)))

        # CoE/SDO options
        self.sdo_read_cmd = args.get("sdo_read", args.get("sdo-read", ""))
        self.sdo_write_cmd = args.get("sdo_write", args.get("sdo-write", ""))
        self.eeprom_write_cmd = args.get("eeprom-write", args.get("eeprom_write", ""))
        self.set_alias_cmd = args.get("set-alias", args.get("set_alias", ""))
        self.set_coe_cmd = args.get("set-coe", args.get("set_coe", ""))
        self.set_mailbox_cmd = args.get("set-mailbox", args.get("set_mailbox", ""))

        # CoE range override
        self.coe_range = args.get("coe-range", args.get("coe_range", ""))
        self.confirm = parse_bool(args.get("confirm", False))

        # Emergency messages storage
        self.emergency_messages: List[Dict[str, Any]] = []

        # Processdata thread for OP state
        self._pd_thread: Optional[threading.Thread] = None
        self._pd_thread_stop = threading.Event()
        self._actual_wkc = 0

    def get_protocol_name(self) -> str:
        return "EtherCAT"

    def get_default_port(self) -> int:
        return 0  # Not applicable for EtherCAT

    def check_dependencies(self) -> bool:
        return _pysoem.is_available

    def connect(self) -> Any:
        """Initialize EtherCAT master"""
        pysoem = _get_pysoem()
        try:
            # Check for raw socket capabilities
            has_capability, error_msg = check_raw_socket_capability()
            if not has_capability:
                self.logger.fail(error_msg)
                return None

            master = pysoem.Master()

            # Open interface - pysoem.open() returns None on success, raises on failure
            try:
                master.open(self.interface)
            except Exception as e:
                self.logger.fail(f"Failed to open EtherCAT interface: {self.interface}: {e}")
                return None

            # Discover slaves
            slave_count = master.config_init()
            if slave_count == 0:
                self.logger.warning("No EtherCAT slaves found on network")
                return master  # Return anyway for potential manual operations

            self.logger.display(f"Found {slave_count} EtherCAT slaves")

            # If boot state requested, transition to Bootstrap (for FoE firmware ops).
            # Bootstrap state lets the master flash slave firmware — strictly a
            # write/state-change operation, so gate it behind --confirm.
            if self.boot_state:
                if not self.confirm:
                    self.logger.fail(
                        "--boot-state requires --confirm (transitions slaves into "
                        "Bootstrap firmware-update state, disrupting operation)"
                    )
                    return master
                self._transition_to_boot(master, pysoem)
                return master

            # Configure slaves (normal operation path)
            config_map_ok = False
            try:
                master.config_map()
                config_map_ok = True
                self.logger.debug(f"config_map() complete, expected_wkc={master.expected_wkc}")
            except pysoem.ConfigMapError as e:
                # config_map() failed — PDO mapping errors during Object Dictionary reads
                # Log details but continue — master is still usable in PRE-OP for SDO/mailbox
                err_types = {}
                for err in e.error_list:
                    key = f"{type(err).__name__}: {err}"
                    err_types[key] = err_types.get(key, 0) + 1
                self.logger.warning(
                    f"PDO mapping failed ({len(e.error_list)} error(s)), continuing in PRE-OP"
                )
                for desc, count in err_types.items():
                    self.logger.debug(f"  {desc} (x{count})" if count > 1 else f"  {desc}")

            if config_map_ok:
                # Configure Distributed Clocks (required for OP state on many devices)
                master.config_dc()
                self.logger.debug("Distributed Clocks configured")

                # Check expected working counter
                if master.expected_wkc > 0:
                    # First transition to SAFEOP
                    master.state_check(pysoem.SAFEOP_STATE, 50000)
                    self.logger.display("EtherCAT network reached SAFE-OP state")

                    # If OP state requested, transition to OP. OP energises
                    # process outputs on real slaves, so gate it behind --confirm.
                    if self.op_state:
                        if not self.confirm:
                            self.logger.fail(
                                "--op-state requires --confirm (transitions slaves "
                                "into OPERATIONAL, energising process outputs)"
                            )
                        else:
                            self._transition_to_op(master, pysoem)
                else:
                    self.logger.warning("expected_wkc is 0, skipping state transition")

            if not config_map_ok or master.expected_wkc == 0:
                if self.op_state:
                    self.logger.fail(
                        "Cannot transition to OP: PDO mapping failed. "
                        "Fix config_map errors or scan without --op-state."
                    )
                # Try to force PRE-OP for mailbox/SDO access even without PDO mapping
                try:
                    for slave in master.slaves:
                        slave.state = pysoem.PREOP_STATE
                        slave.write_state()
                    master.state_check(pysoem.PREOP_STATE, 50000)
                    self.logger.display("Forced PRE-OP state for mailbox access")
                except Exception as e:
                    self.logger.debug(f"Failed to force PRE-OP: {e}")

            return master

        except Exception as e:
            self.logger.fail(f"Failed to initialize EtherCAT master: {e}")
            return None

    def _processdata_thread(self, master: Any):
        """Background thread for cyclic PDO exchange (required for OP state)"""
        while not self._pd_thread_stop.is_set():
            try:
                master.send_processdata()
                self._actual_wkc = master.receive_processdata(10000)
                time.sleep(0.001)  # 1ms cycle
            except Exception as e:
                self.logger.debug(f"Processdata thread exiting: {e}")
                break

    def _transition_to_op(self, master: Any, pysoem: Any):
        """Transition all slaves to OP state"""
        self.logger.warning("Transitioning to OP state - outputs will be ENABLED!")

        # Exchange initial process data (required before OP transition)
        self.logger.display("Sending initial process data...")
        master.send_processdata()
        wkc = master.receive_processdata(10000)
        self.logger.display(f"Initial WKC: {wkc}/{master.expected_wkc}")

        # Start processdata thread (required for OP)
        self._pd_thread_stop.clear()
        self._pd_thread = threading.Thread(
            target=self._processdata_thread, args=(master,), daemon=True
        )
        self._pd_thread.start()
        time.sleep(0.1)  # Let thread start

        # Request OP state for each slave individually
        for slave in master.slaves:
            slave.state = pysoem.OP_STATE
        master.write_state()

        # Wait for slaves to reach OP with better checking
        # pysoem.OP_STATE = 8
        self.logger.display(f"Waiting for slaves to reach OP (target state: {pysoem.OP_STATE})...")
        op_reached = False
        for attempt in range(20):  # Reduced from 40
            master.state_check(pysoem.OP_STATE, 10000)  # 10ms timeout

            # Read current states
            master.read_state()

            # Check all individual slave states
            all_op = True
            for i, slave in enumerate(master.slaves):
                # OP_STATE = 8, check base state (ignore error flag)
                slave_base_state = slave.state & 0x0F
                if slave_base_state != 8:  # OP_STATE = 8
                    all_op = False
                if attempt % 10 == 0:  # Debug every 10 attempts
                    self.logger.debug(
                        f"  Attempt {attempt}: Slave {i + 1} state={slave.state} (base={slave_base_state})"
                    )

            if all_op:
                op_reached = True
                break

            time.sleep(0.05)

        # Final state report
        self.logger.display(
            f"Master state: {master.state} ({self._get_slave_state_name(master.state)})"
        )
        self.logger.display(f"Working counter: {self._actual_wkc}/{master.expected_wkc}")

        # Show individual slave states with details
        for i, slave in enumerate(master.slaves):
            state_name = self._get_slave_state_name(slave.state)
            al_status = getattr(slave, "al_status", 0)
            slave_base_state = slave.state & 0x0F

            if slave_base_state == 8:  # OP_STATE
                self.logger.success(f"  Slave {i + 1}: {state_name} (state={slave.state})")
            elif slave.state & 0x10:  # Error flag
                error_msg = self._get_al_status_error(al_status)
                self.logger.fail(f"  Slave {i + 1}: {state_name} - {error_msg} (0x{al_status:04X})")
            else:
                self.logger.warning(f"  Slave {i + 1}: {state_name} (state={slave.state})")

        if op_reached:
            self.logger.success("All slaves reached OP state - outputs ENABLED")
        else:
            self.logger.fail("Not all slaves reached OP state - check AL Status for errors")

    def _transition_to_boot(self, master: Any, pysoem: Any):
        """Transition slaves to Bootstrap state for FoE firmware operations."""
        self.logger.warning("Transitioning to BOOTSTRAP state for firmware operations...")

        # Check if any slave supports Bootstrap mode
        boot_supported = []
        for i, slave in enumerate(master.slaves):
            # Read bootstrap mailbox config from EEPROM
            try:
                d = slave.eeprom_read(0x11)  # Bootstrap RX size at word 0x11
                boot_rx_size = struct.unpack("<H", d[:2])[0]
                if boot_rx_size > 0:
                    boot_supported.append(i + 1)
                    self.logger.display(
                        f"  Slave {i + 1}: Bootstrap mailbox configured (size={boot_rx_size})"
                    )
                else:
                    self.logger.warning(
                        f"  Slave {i + 1}: No bootstrap mailbox - FoE not supported"
                    )
            except Exception as e:
                self.logger.warning(f"  Slave {i + 1}: Failed to read bootstrap config: {e}")

        if not boot_supported:
            self.logger.warning("No slaves have bootstrap mailbox configured")
            self.logger.display("  Attempting transition anyway to see slave response...")

        # Request BOOT state for each slave
        for slave in master.slaves:
            slave.state = pysoem.BOOT_STATE
        master.write_state()

        # Wait for transition
        time.sleep(0.1)
        master.read_state()

        # Check results
        for i, slave in enumerate(master.slaves):
            state_name = self._get_slave_state_name(slave.state)
            if slave.state == pysoem.BOOT_STATE:
                self.logger.success(f"  Slave {i + 1}: {state_name} - FoE available")
            elif slave.state & 0x10:  # Error flag
                al_status = getattr(slave, "al_status", 0)
                error_msg = self._get_al_status_error(al_status)
                self.logger.fail(f"  Slave {i + 1}: {state_name} - {error_msg} (0x{al_status:04X})")
            else:
                self.logger.warning(f"  Slave {i + 1}: {state_name} (expected BOOT)")

        self.logger.display("Bootstrap transition complete")

    def disconnect(self, connection: Any) -> None:
        """Close EtherCAT master connection"""
        # Stop processdata thread first
        if self._pd_thread and self._pd_thread.is_alive():
            self._pd_thread_stop.set()
            self._pd_thread.join(timeout=2.0)
            self._pd_thread = None
            self.logger.debug("Processdata thread stopped")

        if connection:
            try:
                pysoem = _get_pysoem()
                # Transition all slaves to INIT state for clean shutdown
                for slave in connection.slaves:
                    slave.state = pysoem.INIT_STATE
                connection.write_state()
                time.sleep(0.1)  # Give slaves time to transition

                # Verify transition (optional, for debugging)
                connection.read_state()

                # Close the master interface
                connection.close()
                self.logger.debug("EtherCAT master closed")
            except Exception as e:
                # Try to close anyway even if state transition failed.
                # NOTE: previously the inner `except Exception as e:`
                # shadowed the outer 'e' and Python 3's except-variable
                # scoping deleted it after the inner suite, so line 488
                # raised UnboundLocalError when the inner close failed
                # — losing the original cleanup error completely. Rename
                # the inner variable.
                try:
                    connection.close()
                except Exception as close_err:
                    self.logger.debug(f"connection.close(): {close_err}")
                self.logger.debug(f"Error during EtherCAT cleanup: {e}")

    def discover(self, connection: Any) -> Dict[str, Any]:
        """Perform EtherCAT discovery"""
        results = {
            "network_info": {},
            "slaves": {},
            "sdo_data": {},
            "eeprom_data": {},
            "eeprom_raw": {},
            "dc_analysis": {},
            "foe_results": {},
            "emergency_messages": [],
            "fuzzing_results": {},
            "fsoe_data": {},
            "security_analysis": {},
        }

        # Setup emergency monitoring if enabled
        if self.emergency_monitor:
            self._setup_emergency_callbacks(connection)

        # Get network information
        results["network_info"] = self._get_network_info(connection)

        # Discover slaves
        results["slaves"] = self._discover_slaves(connection)

        # Enrich with SDO reads if -i
        if self.device_info:
            self._enrich_device_info(connection, results["slaves"])

        # Always display tree view
        self._display_slave_tree(results["network_info"], results["slaves"])

        # ESC register debug (for diagnosing state transition issues)
        if self.esc_debug:
            results["esc_debug"] = self._dump_esc_registers(connection)

        # Distributed Clock analysis
        if self.dc_analysis:
            results["dc_analysis"] = self._analyze_distributed_clock(connection)

        if self.read_eeprom and (self.device_info or self.dump_path):
            results["eeprom_data"] = self._read_eeprom_data(connection)

        # Full EEPROM dump
        if self.eeprom_dump:
            results["eeprom_raw"] = self._dump_full_eeprom(connection)

        # Parse EEPROM/ESI structure
        if self.eeprom_parse:
            results["eeprom_parsed"] = self._parse_eeprom_esi(connection)

        # EEPROM write operations (requires --confirm)
        if self.eeprom_write_cmd:
            if self.confirm:
                results["eeprom_write_result"] = self._execute_eeprom_write(connection)
            else:
                self.logger.fail("EEPROM write requires --confirm flag (write operation)")

        # Set station alias (requires --confirm)
        if self.set_alias_cmd:
            if self.confirm:
                results["set_alias_result"] = self._execute_set_alias(connection)
            else:
                self.logger.fail("--set-alias requires --confirm flag (write operation)")

        # Set CoE capabilities (requires --confirm)
        if self.set_coe_cmd:
            if self.confirm:
                results["set_coe_result"] = self._execute_set_coe(connection)
            else:
                self.logger.fail("--set-coe requires --confirm flag (write operation)")

        # Set mailbox protocols (requires --confirm)
        if self.set_mailbox_cmd:
            if self.confirm:
                results["set_mailbox_result"] = self._execute_set_mailbox(connection)
            else:
                self.logger.fail("--set-mailbox requires --confirm flag (write operation)")

        if self.read_sdo and (self.device_info or self.dump_path):
            results["sdo_data"] = self._read_sdo_data(connection)

        # Full CoE object dictionary scan
        if self.sdo_scan:
            results["coe_dictionary"] = self._scan_coe_dictionary(connection)

        # FSoE safety object scan
        if self.scan_fsoe:
            results["fsoe_data"] = self._scan_fsoe(connection)

        # SDO read command
        if self.sdo_read_cmd:
            results["sdo_read_result"] = self._execute_sdo_read(connection)

        # SDO write command (requires --confirm)
        if self.sdo_write_cmd:
            if self.confirm:
                results["sdo_write_result"] = self._execute_sdo_write(connection)
            else:
                self.logger.fail("--sdo-write requires --confirm flag (write operation)")

        # FoE operations
        if self.foe_read:
            results["foe_results"]["read"] = self._foe_read_file(connection)
        if self.foe_write:
            if self.confirm:
                results["foe_results"]["write"] = self._foe_write_file(connection)
            else:
                self.logger.fail("--foe-write requires --confirm flag (write operation)")

        # Fuzzing operations (requires --confirm)
        if self.fuzz_sdo or self.fuzz_pdo:
            if self.confirm:
                self.logger.display("Performing EtherCAT fuzzing (potentially dangerous)")
                results["fuzzing_results"] = self._perform_fuzzing(connection)
            else:
                self.logger.fail("--fuzz requires --confirm flag (dangerous operation)")

        # Collect emergency messages
        results["emergency_messages"] = self.emergency_messages

        # Security analysis
        results["security_analysis"] = self._analyze_security(results)

        # Export data if requested
        if self.dump_path:
            self._export_dump_data(results)

        # Report findings
        self._report_findings(results)

        return results

    def _get_network_info(self, master: Any) -> Dict[str, Any]:
        """Get EtherCAT network information"""
        info = {
            "interface": self.interface,
            "slave_count": len(master.slaves),
            "expected_wkc": getattr(master, "expected_wkc", 0),
            "actual_wkc": 0,
            "cycle_time": 0,
            "timestamp": datetime.now().isoformat(),
        }

        try:
            # Get working counter
            info["actual_wkc"] = master.receive_processdata(2000)

            # Estimate cycle time
            start_time = time.time()
            for _ in range(10):
                master.send_processdata()
                master.receive_processdata(2000)
            cycle_time = (time.time() - start_time) / 10 * 1000  # ms
            info["cycle_time"] = round(cycle_time, 2)

        except Exception as e:
            self.logger.debug(f"Error getting network info: {e}")

        return info

    def _discover_slaves(self, master: Any) -> Dict[int, Any]:
        """Discover EtherCAT slaves (data collection only, no display)."""
        slaves = {}
        targets = self._slave_filter()

        for i in range(len(master.slaves)):
            position = i + 1
            if position not in targets:
                continue

            slave = master.slaves[i]

            # Get name - handle bytes or string
            name = slave.name
            if isinstance(name, bytes):
                name = name.decode("utf-8", errors="ignore").strip("\x00") if name else ""
            if not name:
                name = f"Slave_{i + 1}"

            al_status = getattr(slave, "al_status", 0)

            slaves[i + 1] = {
                "position": i + 1,
                "name": name,
                "manufacturer": lookup_vendor(slave.man),
                "manufacturer_id": slave.man,
                "product_code": slave.id,
                "revision": slave.rev,
                "fw_version": "",
                "hw_version": "",
                "device_name_sdo": "",
                "state": self._get_slave_state_name(slave.state),
                "state_code": slave.state,
                "al_status": al_status,
                "al_status_error": self._get_al_status_error(al_status) if al_status else None,
                "io_map": {
                    "input_bytes": len(slave.input) if slave.input else 0,
                    "output_bytes": len(slave.output) if slave.output else 0,
                },
                "timestamp": datetime.now().isoformat(),
            }

        return slaves

    def _slave_filter(self) -> set:
        """Return slave positions to operate on.

        Respects both --scan-range and --slave.
        """
        positions = set(self.slave_positions)
        if self.slave is not None:
            return positions & {self.slave}
        return positions

    def _enrich_device_info(self, master: Any, slaves: Dict[str, Any]):
        """Read SDO identity/version objects and enrich the slaves dict (--device-info / -i)."""
        from .coe import COMMON_SDO_OBJECTS

        targets = self._slave_filter()
        self.logger.display("Reading device information via SDO...")

        for slave_idx in range(len(master.slaves)):
            position = slave_idx + 1
            if position not in targets:
                continue

            slave = master.slaves[slave_idx]
            slave_info = slaves.get(position, {})

            for index, subindex, description in COMMON_SDO_OBJECTS:
                try:
                    data = slave.sdo_read(index, subindex)
                    if data is not None:
                        if len(data) <= 4:
                            value = int.from_bytes(data, "little")
                            if index == 0x1000:
                                slave_info["device_type"] = f"0x{value:08X}"
                            elif index == 0x1001:
                                slave_info["error_register"] = value
                            elif index == 0x1018 and subindex == 3:
                                slave_info["revision_sdo"] = f"0x{value:08X}"
                            elif index == 0x1018 and subindex == 4:
                                slave_info["serial_number"] = f"0x{value:08X}"
                        else:
                            text = data.decode("utf-8", errors="ignore").rstrip("\x00")
                            if text and all(c.isprintable() or c.isspace() for c in text):
                                if index == 0x1008:
                                    slave_info["device_name_sdo"] = text
                                elif index == 0x1009:
                                    slave_info["hw_version"] = text
                                elif index == 0x100A:
                                    slave_info["fw_version"] = text
                except Exception as e:
                    self.logger.debug(f"EtherCAT common SDO read/decode failed: {e}")

    def _scan_fsoe(self, master: Any) -> Dict[str, Any]:
        """Scan FSoE (Functional Safety) CoE objects from slaves."""
        from .fsoe import FSOE_COE_OBJECTS, FSOE_PARAM_OBJECTS

        all_objects = FSOE_COE_OBJECTS + FSOE_PARAM_OBJECTS

        self.logger.display("Scanning FSoE safety objects...")
        fsoe_data = {}
        targets = self._slave_filter()

        for slave_idx, slave in enumerate(master.slaves):
            position = slave_idx + 1
            if position not in targets:
                continue

            slave_results = []
            for index, subindex, name, dtype, read_size in all_objects:
                try:
                    data = slave.sdo_read(index, subindex)
                    if data is None:
                        continue

                    entry = {
                        "index": f"0x{index:04X}",
                        "subindex": subindex,
                        "name": name,
                        "type": dtype,
                        "raw": data.hex(),
                        "size": len(data),
                    }

                    if dtype in ("uint8", "uint16", "uint32") and len(data) <= 4:
                        entry["value"] = int.from_bytes(data, "little")
                    elif dtype == "string":
                        text = data.decode("utf-8", errors="ignore").rstrip("\x00")
                        if text and all(c.isprintable() or c.isspace() for c in text):
                            entry["value"] = text
                        else:
                            entry["value"] = data.hex()
                    else:
                        entry["value"] = data.hex()

                    slave_results.append(entry)
                except Exception as e:
                    self.logger.debug(f"EtherCAT FSoE SDO read/decode failed: {e}")

            if slave_results:
                fsoe_data[position] = slave_results
                self.logger.display(f"  Slave {position}: {len(slave_results)} FSoE objects found")

                table_data = []
                for entry in slave_results:
                    table_data.append(
                        [
                            entry["index"],
                            str(entry["subindex"]),
                            entry["name"],
                            str(entry["value"]),
                        ]
                    )
                from ...utils.export_utils import print_table

                print_table(
                    table_data,
                    ["Index", "Sub", "Name", "Value"],
                    title=f"FSoE Objects (Slave {position})",
                    logger=self.logger,
                )
            else:
                self.logger.display(f"  Slave {position}: no FSoE objects (not a safety device)")

        if not fsoe_data:
            self.logger.display("  No FSoE-capable slaves found")

        return fsoe_data

    def _display_slave_tree(self, network_info: Dict[str, Any], slaves: Dict[str, Any]):
        """Render EtherCAT network as a tree view."""
        slave_count = len(slaves)
        self.logger.display(
            f"EtherCAT Network ({self.interface}, {slave_count} slave{'s' if slave_count != 1 else ''})"
        )

        sorted_positions = sorted(slaves.keys())
        for i, pos in enumerate(sorted_positions):
            info = slaves[pos]
            is_last = i == len(sorted_positions) - 1
            branch = "└── " if is_last else "├── "
            indent = "    " if is_last else "│   "

            # Slave header line
            self.logger.display(f"{branch}Slave {pos}: {info['name']}")

            # Build detail lines (compact: manufacturer + state/IO only)
            details = []
            details.append(
                f"{info['manufacturer']} (0x{info['manufacturer_id']:04X}:0x{info['product_code']:08X})"
            )

            # State + I/O
            io = info.get("io_map", {})
            state_line = f"State: {info['state']}"
            io_in = io.get("input_bytes", 0)
            io_out = io.get("output_bytes", 0)
            if io_in or io_out:
                state_line += f" | I/O: {io_in} in / {io_out} out"
            details.append(state_line)

            # Render detail lines with tree connectors
            for j, detail in enumerate(details):
                is_last_detail = j == len(details) - 1
                sub_branch = "└── " if is_last_detail else "├── "
                self.logger.display(f"{indent}{sub_branch}{detail}")

    def _get_slave_state_name(self, state_code: int) -> str:
        """Convert state code to readable name. Delegates to constants module."""
        return get_slave_state_name(state_code)

    def _get_al_status_error(self, al_status_code: int) -> str:
        """Decode AL Status Code. Delegates to constants module."""
        return get_al_status_error(al_status_code)


# Create metadata and run function using protocol module factory
metadata, run = create_protocol_module(
    EtherCATScanner, dependencies_check_func=lambda: not _pysoem.is_available
)


if __name__ == "__main__":
    # Standalone mode
    cli_run(metadata, run)


# NXC-style callable class
from .nxc_connection import ethercat  # noqa: E402, F401
