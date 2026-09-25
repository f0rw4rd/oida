"""Advanced operations mixin for EtherCATScanner (ESC, DC, Emergency, FoE)."""

from __future__ import annotations

import os
import struct
from typing import Any, Dict, TYPE_CHECKING
from datetime import datetime
from binascii import hexlify

from oida.utils.export_utils import print_table


if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


def _u16le(data: Any) -> int | None:
    """Decode a little-endian u16 from a device-supplied register read.

    Returns None when the slave answered with fewer than 2 bytes (or with
    something that isn't bytes at all) instead of raising struct.error.
    """
    if not isinstance(data, (bytes, bytearray)) or len(data) < 2:
        return None
    return int(struct.unpack_from("<H", data, 0)[0])


class AdvancedOpsMixin(_ScannerBase):
    """Mixin providing ESC register debug, DC analysis, emergency monitoring, and FoE."""

    def _dump_esc_registers(self, master: Any) -> Dict[int, Any]:
        """Dump ESC registers for debugging state transition issues.

        Key registers per ETG.1000:
        - 0x0120: AL Control (requested state)
        - 0x0130: AL Status (current state)
        - 0x0134: AL Status Code (error code)
        - 0x0800-0x083F: SyncManager config (8 bytes each, SM0-SM7)
        - 0x0600-0x06FF: FMMU config (16 bytes each, FMMU0-FMMU15)
        - 0x0980/0x0981: DC Cycle Unit Control / DC Activation
        """
        self.logger.display("Dumping ESC registers for debug...")
        results = {}

        for i, slave in enumerate(master.slaves):
            slave_data = {"position": i + 1}

            def read_reg(addr: int, size: int) -> bytes:
                """Read ESC register via FPRD"""
                try:
                    if hasattr(slave, "_fprd"):
                        data = slave._fprd(addr, size)
                        if isinstance(data, (bytes, bytearray)):
                            return bytes(data)
                        self.logger.debug(
                            "FPRD read of 0x%04X returned non-bytes: %r", addr, type(data)
                        )
                except Exception as e:
                    self.logger.debug("FPRD read of 0x%04X failed: %s", addr, e)
                return b""

            # AL Status registers
            al_status_data = read_reg(0x0130, 2)
            al_code_data = read_reg(0x0134, 2)

            al_status = _u16le(al_status_data)
            if al_status is not None:
                slave_data["al_status"] = {
                    "raw": f"0x{al_status:04X}",
                    "state": self._get_slave_state_name(al_status),
                }
            elif al_status_data:
                self.logger.debug("Truncated AL Status (0x0130) read: %r", al_status_data)

            al_code = _u16le(al_code_data)
            if al_code is not None:
                slave_data["al_status_code"] = {
                    "raw": f"0x{al_code:04X}",
                    "meaning": self._get_al_status_error(al_code),
                }
            elif al_code_data:
                self.logger.debug("Truncated AL Status Code (0x0134) read: %r", al_code_data)

            # SyncManager configuration
            slave_data["sync_managers"] = []
            sm_headers = ["SM", "Start", "Len", "Ctrl", "Status", "Active", "Type"]
            sm_rows = []

            for sm in range(4):
                base = 0x0800 + (sm * 8)
                sm_data = read_reg(base, 8)
                if sm_data and len(sm_data) >= 8:
                    start = struct.unpack("<H", sm_data[0:2])[0]
                    length = struct.unpack("<H", sm_data[2:4])[0]
                    ctrl = sm_data[4]
                    status = sm_data[5]
                    activate = sm_data[6]

                    # Decode SM type by position (SM0=mbx_out, SM1=mbx_in,
                    # SM2=pdo_out, SM3=pdo_in) - positional heuristic per ETG.1000
                    sm_types = {1: "mbx_out", 2: "mbx_in", 3: "pdo_out", 4: "pdo_in"}
                    sm_type = sm_types.get(sm + 1, f"type_{sm}")

                    # Decode status bits
                    status_bits = []
                    if status & 0x01:
                        status_bits.append("INT_WR")
                    if status & 0x02:
                        status_bits.append("INT_RD")
                    if status & 0x08:
                        status_bits.append("FULL")
                    if status & 0x10:
                        status_bits.append("RD_OP")
                    if status & 0x20:
                        status_bits.append("WR_OP")

                    sm_info = {
                        "sm": sm,
                        "start": f"0x{start:04X}",
                        "length": length,
                        "control": f"0x{ctrl:02X}",
                        "status": f"0x{status:02X}",
                        "status_bits": status_bits,
                        "activate": activate,
                    }
                    slave_data["sync_managers"].append(sm_info)
                    sm_rows.append(
                        [
                            f"SM{sm}",
                            f"0x{start:04X}",
                            str(length),
                            f"0x{ctrl:02X}",
                            f"0x{status:02X} ({','.join(status_bits) if status_bits else '-'})",
                            "Yes" if activate else "No",
                            sm_type,
                        ]
                    )

            # FMMU configuration
            slave_data["fmmu"] = []
            fmmu_rows = []

            for fmmu in range(4):
                base = 0x0600 + (fmmu * 16)
                fmmu_data = read_reg(base, 16)
                if fmmu_data and len(fmmu_data) >= 13:
                    log_start = struct.unpack("<I", fmmu_data[0:4])[0]
                    log_len = struct.unpack("<H", fmmu_data[4:6])[0]
                    phys_start = struct.unpack("<H", fmmu_data[8:10])[0]
                    fmmu_type = fmmu_data[11]
                    activate = fmmu_data[12]

                    if activate:
                        type_name = {1: "read", 2: "write"}.get(fmmu_type, f"type_{fmmu_type}")
                        fmmu_info = {
                            "fmmu": fmmu,
                            "logical_start": f"0x{log_start:08X}",
                            "length": log_len,
                            "physical_start": f"0x{phys_start:04X}",
                            "type": type_name,
                            "active": True,
                        }
                        slave_data["fmmu"].append(fmmu_info)
                        fmmu_rows.append(
                            [
                                f"FMMU{fmmu}",
                                f"0x{log_start:08X}",
                                str(log_len),
                                f"0x{phys_start:04X}",
                                type_name,
                            ]
                        )

            # DC configuration. The DC Activation register is the single byte
            # at 0x0981 (0x0980 is the DC Cycle Unit Control reserved byte);
            # read both so the raw value keeps the real register alignment.
            dc_data = read_reg(0x0980, 2)
            dc_active = _u16le(dc_data)
            if dc_active is not None:
                slave_data["dc_activation"] = f"0x{dc_active >> 8:02X}"
                slave_data["dc_enabled"] = bool(dc_active & 0x0300)
            elif dc_data:
                self.logger.debug("Truncated DC Activation (0x0981) read: %r", dc_data)

            # Watchdog config
            # 0x0400 is the shared Watchdog Divider register (ET1100/ESC reg
            # map; pysoem's ECT_REG_WD_DIV). 0x0420 is a different value - the
            # Watchdog Time Process Data - and was previously misread here.
            wd_div = read_reg(0x0400, 2)
            wd_value = _u16le(wd_div)
            if wd_value is not None:
                slave_data["watchdog_divider"] = wd_value
            elif wd_div:
                self.logger.debug("Truncated Watchdog Divider (0x0400) read: %r", wd_div)

            # Process-data watchdog time (units of divider*40ns base).
            wd_time_pd = read_reg(0x0420, 2)
            wd_time_value = _u16le(wd_time_pd)
            if wd_time_value is not None:
                slave_data["watchdog_time_process_data"] = wd_time_value

            results[i + 1] = slave_data

            # Display for this slave
            self.logger.display(f"\n=== Slave {i + 1} ESC Registers ===")

            if "al_status" in slave_data:
                al = slave_data["al_status"]
                self.logger.display(f"AL Status: {al['raw']} ({al['state']})")
            if "al_status_code" in slave_data:
                code = slave_data["al_status_code"]
                self.logger.display(f"AL Status Code: {code['raw']} - {code['meaning']}")

            if sm_rows:
                self.logger.display("\nSyncManagers:")
                print_table(sm_rows, sm_headers, logger=self.logger)

            if fmmu_rows:
                self.logger.display("\nFMMU:")
                print_table(
                    fmmu_rows, ["FMMU", "Logical", "Len", "Physical", "Type"], logger=self.logger
                )

            if "dc_activation" in slave_data:
                dc = slave_data["dc_activation"]
                enabled = "Yes" if slave_data.get("dc_enabled") else "No"
                self.logger.display(f"\nDC Activation: {dc} (Enabled: {enabled})")

            if "watchdog_divider" in slave_data:
                self.logger.display(f"Watchdog Divider: {slave_data['watchdog_divider']}")
            if "watchdog_time_process_data" in slave_data:
                self.logger.display(
                    f"Watchdog Time Process Data: {slave_data['watchdog_time_process_data']}"
                )

        return results

    def _setup_emergency_callbacks(self, master: Any) -> None:
        """Setup emergency message callbacks for all slaves (pysoem 1.1.7+)"""
        self.logger.debug("Setting up emergency message monitoring...")

        def create_callback(slave_pos: int):
            """Create emergency callback for a specific slave"""

            def emergency_handler(emergency):
                msg = {
                    "slave_position": slave_pos,
                    "timestamp": datetime.now().isoformat(),
                    "error_code": getattr(emergency, "error_code", 0),
                    # pysoem Emergency fields are error_reg + b1/w1/w2 (there is
                    # no error_register / data attribute), so the old names
                    # always returned the 0/b"" defaults.
                    "error_register": getattr(emergency, "error_reg", 0),
                    "data": hexlify(
                        struct.pack(
                            "<BHH",
                            getattr(emergency, "b1", 0),
                            getattr(emergency, "w1", 0),
                            getattr(emergency, "w2", 0),
                        )
                    ).decode(),
                }
                self.emergency_messages.append(msg)
                self.logger.warning(
                    f"Emergency from slave {slave_pos}: "
                    f"Code=0x{msg['error_code']:04X} Reg=0x{msg['error_register']:02X}"
                )

            return emergency_handler

        for i in range(len(master.slaves)):
            try:
                slave = master.slaves[i]
                if hasattr(slave, "add_emergency_callback"):
                    slave.add_emergency_callback(create_callback(i + 1))
                    self.logger.debug(f"Emergency callback registered for slave {i + 1}")
            except Exception as e:
                self.logger.debug(f"Could not setup emergency callback for slave {i + 1}: {e}")

    def _analyze_distributed_clock(self, master: Any) -> Dict[str, Any]:
        """Analyze Distributed Clock synchronization (pysoem 1.1.x)"""
        self.logger.display("Analyzing Distributed Clock...")
        dc_info = {
            "dc_time": 0,
            "dc_configured": False,
            "slaves_with_dc": [],
            "sync_errors": [],
        }

        try:
            # Configure DC
            master.config_dc()
            dc_info["dc_configured"] = True
            self.logger.display("DC configuration completed")

            # Get DC time
            if hasattr(master, "dc_time"):
                dc_info["dc_time"] = master.dc_time
                self.logger.display(f"DC Time: {dc_info['dc_time']} ns")

            # Check each slave for DC support
            for i in range(len(master.slaves)):
                slave = master.slaves[i]
                slave_dc = {
                    "position": i + 1,
                    "has_dc": hasattr(slave, "dc_sync"),
                    "dc_cycle": 0,
                }

                # Try to get DC info
                if hasattr(slave, "dc_sync"):
                    dc_info["slaves_with_dc"].append(slave_dc)

                # Check for DC-related errors via AL Status Code (ETG.1000 Table 12)
                # DC error codes range 0x0026-0x002C (sync errors, latch errors, etc.)
                al_status = getattr(slave, "al_status", 0)
                if 0x0026 <= al_status <= 0x002C:
                    dc_info["sync_errors"].append(
                        {"slave": i + 1, "al_status": al_status, "error": "DC sync error"}
                    )
                    self.logger.warning(f"Slave {i + 1}: DC sync error detected")

            self.logger.display(f"DC-capable slaves: {len(dc_info['slaves_with_dc'])}")

        except Exception as e:
            self.logger.debug(f"DC analysis error: {e}")
            dc_info["error"] = str(e)

        return dc_info

    def _foe_read_file(self, master: Any) -> Dict[str, Any]:
        """Read file from slave via FoE (File over EtherCAT)"""
        result = {"success": False, "slave": 0, "filename": "", "data": None, "size": 0}

        try:
            # Parse format: slave_pos:filename
            parts = self.foe_read.split(":", 1)
            if len(parts) != 2:
                self.logger.fail("FoE read format: slave_pos:filename")
                result["error"] = "Invalid format"
                return result

            slave_pos = int(parts[0]) - 1  # Convert to 0-based
            filename = parts[1]

            if slave_pos < 0 or slave_pos >= len(master.slaves):
                self.logger.fail(f"Invalid slave position: {slave_pos + 1}")
                result["error"] = "Invalid slave position"
                return result

            slave = master.slaves[slave_pos]
            result["slave"] = slave_pos + 1
            result["filename"] = filename

            self.logger.display(f"FoE: Reading '{filename}' from slave {slave_pos + 1}...")

            # Use pysoem's foe_read method
            if hasattr(slave, "foe_read"):
                data = slave.foe_read(filename, password=0, size=1024 * 1024, timeout=10_000_000)
                result["data"] = hexlify(data).decode() if data else ""
                result["size"] = len(data) if data else 0
                result["success"] = True
                self.logger.success(f"FoE: Read {result['size']} bytes from slave {slave_pos + 1}")

                # Save to dump path if specified
                if self.dump_path and data:
                    from oida.utils.common_types import safe_output_path

                    safe_name = os.path.basename(filename).replace("\x00", "")
                    try:
                        output_file = safe_output_path(
                            f"foe_{slave_pos + 1}_{safe_name}", self.dump_path
                        )
                    except ValueError:
                        self.logger.fail(f"FoE: Unsafe filename blocked: {filename}")
                        return result
                    with open(output_file, "wb") as f:
                        f.write(data)
                    self.logger.display(f"FoE: Saved to {output_file}")
            else:
                result["error"] = "foe_read not available (requires pysoem 1.1.0+)"
                self.logger.fail(result["error"])

        except Exception as e:
            result["error"] = str(e)
            self.logger.fail(f"FoE read failed: {e}")

        return result

    def _foe_write_file(self, master: Any) -> Dict[str, Any]:
        """Write file to slave via FoE (File over EtherCAT)"""
        result = {"success": False, "slave": 0, "filename": "", "size": 0}

        try:
            # Parse format: slave_pos:local_path
            parts = self.foe_write.split(":", 1)
            if len(parts) != 2:
                self.logger.fail("FoE write format: slave_pos:local_path")
                result["error"] = "Invalid format"
                return result

            slave_pos = int(parts[0]) - 1  # Convert to 0-based
            local_path = parts[1]

            if slave_pos < 0 or slave_pos >= len(master.slaves):
                self.logger.fail(f"Invalid slave position: {slave_pos + 1}")
                result["error"] = "Invalid slave position"
                return result

            slave = master.slaves[slave_pos]
            result["slave"] = slave_pos + 1

            # Read local file
            try:
                with open(local_path, "rb") as f:
                    data = f.read()
            except FileNotFoundError:
                result["error"] = f"File not found: {local_path}"
                self.logger.fail(result["error"])
                return result

            filename = os.path.basename(local_path)
            result["filename"] = filename

            self.logger.warning(
                f"FoE: Writing '{filename}' ({len(data)} bytes) to slave {slave_pos + 1}..."
            )

            # Use pysoem's foe_write method
            if hasattr(slave, "foe_write"):
                slave.foe_write(filename, password=0, data=data, timeout=30_000_000)
                result["size"] = len(data)
                result["success"] = True
                self.logger.success(f"FoE: Wrote {len(data)} bytes to slave {slave_pos + 1}")
            else:
                result["error"] = "foe_write not available (requires pysoem 1.1.0+)"
                self.logger.fail(result["error"])

        except Exception as e:
            result["error"] = str(e)
            self.logger.fail(f"FoE write failed: {e}")

        return result
