"""
PROFINET RPC Mixin

Handles RPC read operations:
- I&M data reading (I&M0-I&M3)
- I&M write operations (I&M1, I&M2, I&M3)
- Diagnosis data reading
- Topology (PDRealData) reading
- ModuleDiffBlock configuration validation
- Alarm reading
- Single index read/write
- Slot discovery and display
- AR data and API data
"""

from __future__ import annotations

from typing import Optional, TYPE_CHECKING

from ....utils.vendor_maps import profinet_vendor_map
from ..models import ProfinetDevice

if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


class RPCMixin(_ScannerBase):
    """Mixin providing PROFINET RPC read operations."""

    def _rpc_operations(self, device: ProfinetDevice, profinet_mod) -> None:
        """Perform RPC read operations on device."""
        if not device.ip_address or device.ip_address == "0.0.0.0":
            return

        if not device._dcp_desc:
            self.logger.debug(f"No DCP description for {device.mac_address}, skipping RPC")
            return

        read_diag = self._arg("read_diagnosis", False)
        enum_idx = (
            self._arg("enum", False)
            or self._arg("enum_all", False)
            or self._arg("enum_smart", False)
            or self._arg("enum_range", None)
        )
        show_slots = self._arg("slots", False)
        show_topology = self._arg("topology", False)
        show_module_diff = self._arg("module_diff", False)
        show_alarms = self._arg("alarms", False)
        write_im1 = self._arg("write_im1", None)
        write_im2 = self._arg("write_im2", None)
        write_im3 = self._arg("write_im3", None)

        self.logger.display(f"  RPC connecting to {device.ip_address}...")
        try:
            con = profinet_mod.RPCCon(device._dcp_desc, timeout=self.timeout)
            con.connect(self._my_mac)
            self.logger.display("  RPC connected")
        except Exception as e:
            self.logger.fail(f"  RPC connection failed: {e}")
            self._show_rpc_hint(device)
            return

        read_index = self._arg("read_index", None)
        write_index = self._arg("write_index", None)
        run_cyclic = self._arg("cyclic", False)

        try:
            # Slot discovery if --slots or --cyclic (cyclic needs full topology)
            if show_slots or run_cyclic:
                discovered_slots = self._discover_slots(con)
                if show_slots:
                    self._show_slots(device, discovered_slots, con)
            else:
                discovered_slots = [(0, 1, 0, 0)]

            # Always read I&M0 for basic device info (FW version, order ID)
            self._read_im_data(device, con, profinet_mod)

            if write_index:
                self._write_single_index(device, con, write_index)
            elif read_index:
                self._read_single_index(device, con, read_index)

            if read_diag:
                self._read_diagnosis(device, con, profinet_mod)

            # New 0.6.0 features: topology, module-diff, alarms
            if show_topology:
                self._read_topology(device, con)

            if show_module_diff:
                self._read_module_diff(device, con)

            if show_alarms:
                self._read_alarms(device, con)

            # I&M write operations (use library's high-level API if available)
            pn_dev = device._pn_device
            if write_im1 and self._arg("confirm", False):
                self._write_im1(device, con, write_im1, pn_dev)
            if write_im2 and self._arg("confirm", False):
                self._write_im2(device, con, write_im2, pn_dev)
            if write_im3 and self._arg("confirm", False):
                self._write_im3(device, con, write_im3, pn_dev)

            if enum_idx:
                self._enumerate_indices(device, con, discovered_slots)

            # Handle fuzzing
            fuzz_mode = self._arg("fuzz", None)
            if fuzz_mode:
                self._handle_fuzz(device, con, discovered_slots)
        finally:
            con.close()

        # Cyclic IO test (uses its own RPCCon / AR)
        if run_cyclic:
            import time

            time.sleep(1)  # Let device release previous AR
            self._cyclic_io_test(device, profinet_mod, discovered_slots)

    def _read_im_data(self, device: ProfinetDevice, con, profinet_mod) -> None:
        """Read I&M data from device."""
        try:
            im0 = con.read_im0()
            if im0:
                order_id = (
                    im0.order_id.decode("ascii", errors="ignore").strip()
                    if isinstance(im0.order_id, bytes)
                    else str(im0.order_id).strip()
                )
                serial_num = (
                    im0.im_serial_number.decode("ascii", errors="ignore").strip()
                    if isinstance(im0.im_serial_number, bytes)
                    else str(im0.im_serial_number).strip()
                )
                vendor_id = (im0.vendor_id_high << 8) | im0.vendor_id_low

                sw_rev = (
                    f"{chr(im0.sw_revision_prefix)}"
                    f"{im0.im_sw_revision_functional_enhancement}."
                    f"{im0.im_sw_revision_bug_fix}."
                    f"{im0.im_sw_revision_internal_change}"
                )
                device.im0_data = {
                    "vendor_id": vendor_id,
                    "order_id": order_id,
                    "serial_number": serial_num,
                    "hw_revision": im0.im_hardware_revision,
                    "sw_revision": sw_rev,
                }
                device.firmware_version = sw_rev
                self.logger.display(
                    f"  Order: {order_id}  S/N: {serial_num}"
                    f"  HW: {im0.im_hardware_revision}  FW: {sw_rev}"
                )
        except Exception as e:
            self.logger.debug(f"Failed to read I&M0: {e}")

        try:
            im1 = con.read_im1()
            if im1:
                tag_func = (
                    im1.im_tag_function.decode("ascii", errors="ignore").strip()
                    if hasattr(im1, "im_tag_function") and isinstance(im1.im_tag_function, bytes)
                    else ""
                )
                tag_loc = (
                    im1.im_tag_location.decode("ascii", errors="ignore").strip()
                    if hasattr(im1, "im_tag_location") and isinstance(im1.im_tag_location, bytes)
                    else ""
                )
                device.im1_data = {
                    "tag_function": tag_func,
                    "tag_location": tag_loc,
                }
                if tag_func or tag_loc:
                    self.logger.display(f"  I&M1: {tag_func} @ {tag_loc}")
        except Exception as e:
            self.logger.debug(f"Failed to read I&M1: {e}")

    def _read_im_data_implicit(self, device: ProfinetDevice, con, profinet_mod) -> None:
        """Read I&M data using implicit read (no AR required)."""
        try:
            im0 = con.read_implicit(0, 0, 1, profinet_mod.indices.IM0)
            if im0 and im0.payload:
                parsed = profinet_mod.PNInM0(im0.payload)
                order_id = (
                    parsed.order_id.decode("ascii", errors="ignore").strip()
                    if isinstance(parsed.order_id, bytes)
                    else str(parsed.order_id).strip()
                )
                serial_num = (
                    parsed.im_serial_number.decode("ascii", errors="ignore").strip()
                    if isinstance(parsed.im_serial_number, bytes)
                    else str(parsed.im_serial_number).strip()
                )
                vendor_id = (parsed.vendor_id_high << 8) | parsed.vendor_id_low

                sw_rev = (
                    f"{chr(parsed.sw_revision_prefix)}"
                    f"{parsed.im_sw_revision_functional_enhancement}."
                    f"{parsed.im_sw_revision_bug_fix}."
                    f"{parsed.im_sw_revision_internal_change}"
                )
                device.im0_data = {
                    "vendor_id": vendor_id,
                    "order_id": order_id,
                    "serial_number": serial_num,
                    "hw_revision": parsed.im_hardware_revision,
                    "sw_revision": sw_rev,
                }
                device.firmware_version = sw_rev
                self.logger.success(f"I&M0: {order_id} S/N: {serial_num} FW: {sw_rev}")
        except Exception as e:
            self.logger.debug(f"Failed to read I&M0: {e}")

    def _read_diagnosis(self, device: ProfinetDevice, con, profinet_mod) -> None:
        """Read diagnosis data from device."""
        try:
            diag_data = con.read_diagnosis()
            if diag_data and diag_data.entries:
                device.diagnosis = [
                    {
                        "channel": e.channel_number,
                        # Profinet DiagnosisEntry field is error_type, not
                        # channel_error_type (the old name raised AttributeError
                        # whenever a device returned diagnosis entries).
                        "error_type": e.error_type,
                    }
                    for e in diag_data.entries
                ]
                self.logger.display(f"  Diagnosis: {len(diag_data.entries)} entries")
        except Exception as e:
            self.logger.debug(f"Failed to read diagnosis: {e}")

    def _read_diagnosis_implicit(self, device: ProfinetDevice, con, profinet_mod) -> None:
        """Read diagnosis using implicit read."""
        try:
            diag = con.read_implicit(0, 0, 0, 0xF000)
            if diag and diag.payload:
                self.logger.display(f"Diagnosis data: {len(diag.payload)} bytes")
        except Exception as e:
            self.logger.debug(f"Failed to read diagnosis: {e}")

    def _read_topology(self, device: ProfinetDevice, con) -> None:
        """Read physical topology (PDRealData) from device.

        Displays interface info, port link states, MAU types, and
        LLDP peer information (chassis ID, port ID, management address).
        """
        self.logger.display("  Reading topology (PDRealData)...")
        try:
            pd_real = con.read_pd_real_data()
            device.topology = pd_real

            # Display interface info
            if pd_real.interface:
                iface = pd_real.interface
                self.logger.display(f"  Interface: {iface.chassis_id}")
                self.logger.display(f"    IP: {iface.ip_str}")
                if hasattr(iface, "netmask_str") and iface.netmask_str:
                    self.logger.display(f"    Netmask: {iface.netmask_str}")
                if hasattr(iface, "gateway_str") and iface.gateway_str:
                    self.logger.display(f"    Gateway: {iface.gateway_str}")

            # Display port info
            for port in pd_real.ports:
                link = (
                    "Up"
                    if port.link_state_link == 1
                    else "Down"
                    if port.link_state_link == 2
                    else "Testing"
                )
                mau = port.mau_type_name if port.mau_type_name != "Unknown" else ""
                port_line = f"  Port {port.subslot - 0x8000}: {link}"
                if mau:
                    port_line += f" ({mau})"
                self.logger.display(port_line)

                # Show LLDP peers
                if port.peers:
                    for peer in port.peers:
                        peer_info = f"    Peer: {peer.chassis_id}"
                        if peer.port_id:
                            peer_info += f":{peer.port_id}"
                        if hasattr(peer, "mgmt_addr") and peer.mgmt_addr:
                            peer_info += f" ({peer.mgmt_addr})"
                        self.logger.display(peer_info)
                else:
                    self.logger.display("    No peer detected")

        except Exception as e:
            self.logger.debug(f"Failed to read topology: {e}")

    def _read_module_diff(self, device: ProfinetDevice, con) -> None:
        """Read ModuleDiffBlock to check configuration status.

        Compares expected vs. real module/submodule configuration.
        """
        self.logger.display("  Reading module diff (0xE002)...")
        try:
            diff = con.read_module_diff()
            device.module_diff = diff

            if hasattr(diff, "all_ok") and diff.all_ok:
                self.logger.success("  Configuration matches (all modules OK)")
            else:
                if hasattr(diff, "get_mismatches"):
                    mismatches = diff.get_mismatches()
                    if mismatches:
                        self.logger.warning(f"  {len(mismatches)} configuration mismatch(es):")
                        for slot, subslot, state in mismatches:
                            self.logger.display(f"    Slot {slot} Sub {subslot}: {state}")
                    else:
                        self.logger.success("  Configuration matches")
                elif hasattr(diff, "entries"):
                    self.logger.display(f"  Module diff: {len(diff.entries)} entries")
                else:
                    self.logger.display("  Module diff data retrieved")
        except Exception as e:
            self.logger.debug(f"Failed to read module diff: {e}")

    def _read_alarms(self, device: ProfinetDevice, con) -> None:
        """Read alarm data from device."""
        self.logger.display("  Reading alarms...")
        try:
            result = con.read(api=0, slot=0, subslot=0, idx=0x800C)
            if result and len(result.payload) >= 28:
                from ..helpers import get_alarms_module

                alarms_mod = get_alarms_module()
                if alarms_mod is not None:
                    alarm = alarms_mod.parse_alarm_notification(result.payload)
                    if alarm:
                        alarm_dict = {
                            "type": getattr(
                                alarm,
                                "alarm_type_name",
                                str(alarm.alarm_type),
                            ),
                            # AlarmNotification fields are slot_number /
                            # subslot_number (not slot / subslot).
                            "slot": alarm.slot_number,
                            "subslot": alarm.subslot_number,
                        }
                        device.alarms.append(alarm_dict)
                        self.logger.display(
                            f"  Alarm: {alarm_dict['type']} at "
                            f"slot {alarm.slot_number}/{alarm.subslot_number}"
                        )
                else:
                    self.logger.display(f"  Alarm data: {len(result.payload)} bytes (raw)")
            else:
                self.logger.display("  No alarm data present")
        except Exception as e:
            self.logger.debug(f"Failed to read alarms: {e}")

    def _write_im1(
        self,
        device: ProfinetDevice,
        con,
        values: list,
        pn_dev=None,
    ) -> None:
        """Write I&M1 tag function and location.

        Args:
            values: [tag_function, tag_location] from CLI
            pn_dev: Library ProfinetDevice (optional, for high-level API)
        """
        if len(values) != 2:
            self.logger.fail("--write-im1 requires exactly 2 values: TAG_FUNC TAG_LOC")
            return

        tag_func, tag_loc = values[0], values[1]
        self.logger.display(f"  Writing I&M1: function='{tag_func}' location='{tag_loc}'")

        try:
            if pn_dev and hasattr(pn_dev, "write_im1"):
                # Use library's high-level API
                pn_dev._rpc = con
                pn_dev._connected = True
                pn_dev.write_im1(tag_function=tag_func, tag_location=tag_loc)
            else:
                # Fallback: construct I&M1 block manually
                import struct

                from profinet import indices as idx_module

                header = struct.pack(">HHBBxx", 0x0021, 58, 0x01, 0x00)
                func_bytes = tag_func.encode("latin-1")[:32].ljust(32, b"\x20")
                loc_bytes = tag_loc.encode("latin-1")[:22].ljust(22, b"\x20")
                data = header + func_bytes + loc_bytes
                con.write(
                    api=0,
                    slot=0,
                    subslot=1,
                    idx=idx_module.IM1,
                    data=data,
                )

            self.logger.success("  I&M1 written successfully")
        except Exception as e:
            self.logger.fail(f"  Failed to write I&M1: {e}")

    def _write_im2(
        self,
        device: ProfinetDevice,
        con,
        date_str: str,
        pn_dev=None,
    ) -> None:
        """Write I&M2 installation date.

        Args:
            date_str: Date string (max 16 chars)
            pn_dev: Library ProfinetDevice (optional)
        """
        self.logger.display(f"  Writing I&M2: date='{date_str}'")

        try:
            if pn_dev and hasattr(pn_dev, "write_im2"):
                pn_dev._rpc = con
                pn_dev._connected = True
                pn_dev.write_im2(date=date_str)
            else:
                import struct

                from profinet import indices as idx_module

                header = struct.pack(">HHBBxx", 0x0022, 20, 0x01, 0x00)
                date_bytes = date_str.encode("latin-1")[:16].ljust(16, b"\x20")
                data = header + date_bytes
                con.write(
                    api=0,
                    slot=0,
                    subslot=1,
                    idx=idx_module.IM2,
                    data=data,
                )

            self.logger.success("  I&M2 written successfully")
        except Exception as e:
            self.logger.fail(f"  Failed to write I&M2: {e}")

    def _write_im3(
        self,
        device: ProfinetDevice,
        con,
        descriptor: str,
        pn_dev=None,
    ) -> None:
        """Write I&M3 descriptor.

        Args:
            descriptor: Descriptor string (max 54 chars)
            pn_dev: Library ProfinetDevice (optional)
        """
        self.logger.display(f"  Writing I&M3: descriptor='{descriptor}'")

        try:
            if pn_dev and hasattr(pn_dev, "write_im3"):
                pn_dev._rpc = con
                pn_dev._connected = True
                pn_dev.write_im3(descriptor=descriptor)
            else:
                import struct

                from profinet import indices as idx_module

                header = struct.pack(">HHBBxx", 0x0023, 58, 0x01, 0x00)
                desc_bytes = descriptor.encode("latin-1")[:54].ljust(54, b"\x20")
                data = header + desc_bytes
                con.write(
                    api=0,
                    slot=0,
                    subslot=1,
                    idx=idx_module.IM3,
                    data=data,
                )

            self.logger.success("  I&M3 written successfully")
        except Exception as e:
            self.logger.fail(f"  Failed to write I&M3: {e}")

    def _read_single_index(self, device: ProfinetDevice, con, index_str: str) -> None:
        """Read a single index and display its data."""
        try:
            idx = int(index_str, 0)
        except ValueError:
            self.logger.fail(f"  Invalid index format: {index_str}")
            return

        from ..helpers import get_indices_module

        idx_module = get_indices_module()
        name = idx_module.get_index_name(idx)

        self.logger.display(f"  Reading index 0x{idx:04X} ({name})...")

        try:
            result = con.read(api=0, slot=0, subslot=1, idx=idx)
            if result and len(result.payload) > 0:
                data = result.payload
                self.logger.success(f"  0x{idx:04X} {name} ({len(data)} bytes)")

                # Display hex dump
                for j in range(0, len(data), 32):
                    chunk = data[j : j + 32]
                    hex_str = " ".join(f"{b:02X}" for b in chunk)
                    ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
                    self.logger.display(f"    {hex_str}  {ascii_str}")

                # Try to format value
                val_str = self._format_index_value(data)
                if val_str:
                    self.logger.display(f"  Value: {val_str}")
            else:
                self.logger.fail(f"  Index 0x{idx:04X} returned empty data")
        except Exception as e:
            self.logger.fail(f"  Failed to read index 0x{idx:04X}: {e}")

    def _write_single_index(self, device: ProfinetDevice, con, write_spec: str) -> None:
        """Write data to a single index.

        Format: INDEX:HEXDATA or SLOT/SUBSLOT:INDEX:HEXDATA
        Examples:
            0x8029:01020304
            0/1:0xAFF1:48656C6C6F
        """
        if not self._arg("confirm", False):
            self.logger.fail("--write-index requires --confirm flag")
            return

        slot_arg = self._arg("slot", None)
        slot, subslot = self._parse_slot_arg(slot_arg)
        slot = slot if slot is not None else 0
        subslot = subslot if subslot is not None else 1

        # Parse write specification
        parts = write_spec.split(":")
        if len(parts) < 2:
            self.logger.fail(f"  Invalid write format: {write_spec}")
            self.logger.display("  Use: INDEX:HEXDATA or SLOT/SUBSLOT:INDEX:HEXDATA")
            return

        try:
            if len(parts) == 2:
                idx = int(parts[0], 0)
                hex_data = parts[1]
            elif len(parts) == 3:
                slot_parts = parts[0].split("/")
                slot = int(slot_parts[0])
                subslot = int(slot_parts[1], 0) if len(slot_parts) > 1 else 1
                idx = int(parts[1], 0)
                hex_data = parts[2]
            else:
                self.logger.fail(f"  Invalid write format: {write_spec}")
                return

            data = bytes.fromhex(hex_data)
        except ValueError as e:
            self.logger.fail(f"  Invalid write format: {e}")
            return

        from ..helpers import get_indices_module

        idx_module = get_indices_module()
        name = idx_module.get_index_name(idx)

        self.logger.display(
            f"  Writing {len(data)} bytes to [{slot}/{subslot}] 0x{idx:04X} ({name})..."
        )
        self.logger.display(f"    Data: {hex_data.upper()}")

        if self._arg("read_only", True):
            self.logger.fail(
                "  Write blocked: read-only mode (use --no-read-only to enable writes)"
            )
            return

        try:
            con.write(api=0, slot=slot, subslot=subslot, idx=idx, data=data)
            self.logger.success("  Write successful!")

            try:
                result = con.read(api=0, slot=slot, subslot=subslot, idx=idx)
                if result and result.payload:
                    readback = result.payload
                    readback_hex = " ".join(f"{b:02X}" for b in readback[:32])
                    if len(readback) > 32:
                        readback_hex += "..."
                    self.logger.display(f"  Readback: {readback_hex}")
            except Exception as e:
                self.logger.debug(f"Failed to get result: {e}")
        except Exception as e:
            self.logger.fail(f"  Write failed: {e}")

    def _read_ar_data(self, con) -> Optional[dict]:
        """Read AR (Application Relationship) data via index 0xF820."""
        try:
            result = con.read(api=0, slot=0, subslot=1, idx=0xF820)
            if result and result.payload:
                return {"size": len(result.payload), "data": result.payload}
        except Exception as e:
            self.logger.debug(f"Failed to read AR data: {e}")
        return None

    def _read_api_data(self, con) -> Optional[dict]:
        """Read API data via index 0xF821."""
        try:
            result = con.read(api=0, slot=0, subslot=1, idx=0xF821)
            if result and result.payload:
                return {"size": len(result.payload), "data": result.payload}
        except Exception as e:
            self.logger.debug(f"Failed to read API data: {e}")
        return None

    def _discover_slots(self, con) -> list:
        """Discover all slots and subslots from RealIdentificationData.

        Uses the profinet-py library's discover_slots() method which reads
        index 0xF000 (RealIdentificationData) for complete logical structure.

        Returns: List of (slot, subslot, module_id, submodule_id) tuples
        """
        slots = []

        try:
            slot_infos = con.discover_slots()

            for info in slot_infos:
                slots.append(
                    (
                        info.slot,
                        info.subslot,
                        info.module_ident,
                        info.submodule_ident,
                    )
                )

        except Exception as e:
            self.logger.debug(f"Failed to discover slots: {e}")

        if not slots:
            slots = [(0, 1, 0, 0)]  # Fallback

        return slots

    def _show_slots(
        self,
        device: ProfinetDevice,
        slots: list,
        con=None,
    ) -> None:
        """Display discovered slots/subslots as a tree structure."""
        self.logger.display(f"  Slot/Subslot Structure ({len(slots)} items)")

        # Group slots by slot number
        slot_groups: dict = {}
        for slot, subslot, module_id, submodule_id in slots:
            if slot not in slot_groups:
                slot_groups[slot] = []
            slot_groups[slot].append((subslot, module_id, submodule_id))

        sorted_slots = sorted(slot_groups.keys())

        for i, slot_num in enumerate(sorted_slots):
            subslots = slot_groups[slot_num]
            is_last_slot = i == len(sorted_slots) - 1
            slot_prefix = "\u2514\u2500\u2500 " if is_last_slot else "\u251c\u2500\u2500 "
            child_prefix = "    " if is_last_slot else "\u2502   "

            slot_info = self._get_slot_info(con, slot_num, subslots)
            self.logger.display(f"  {slot_prefix}Slot {slot_num}: {slot_info}")

            sorted_subslots = sorted(subslots, key=lambda x: (x[0] >= 0x8000, x[0]))

            for j, (subslot, module_id, _submodule_id) in enumerate(sorted_subslots):
                is_last_subslot = j == len(sorted_subslots) - 1
                sub_prefix = "\u2514\u2500\u2500 " if is_last_subslot else "\u251c\u2500\u2500 "

                subslot_str = f"0x{subslot:04X}" if subslot >= 0x8000 else str(subslot)

                desc = self._get_slot_description(slot_num, subslot, module_id)
                details = self._get_subslot_details(con, slot_num, subslot, module_id)

                line = f"  {child_prefix}{sub_prefix}[{subslot_str}] {desc}"
                if details:
                    line += f" - {details}"
                self.logger.display(line)

    def _get_slot_info(self, con, slot_num: int, subslots: list) -> str:
        """Get summary info for a slot."""
        if slot_num == 0:
            return "DAP (Device Access Point)"

        for subslot, _module_id, _submodule_id in subslots:
            if subslot == 1 and con:
                try:
                    im0 = con.read_im0(slot=slot_num, subslot=subslot)
                    if im0:
                        order_id = (
                            im0.order_id.decode("ascii", errors="ignore").strip()
                            if isinstance(im0.order_id, bytes)
                            else str(im0.order_id).strip()
                        )
                        if order_id:
                            return order_id
                except Exception as e:
                    self.logger.debug(f"Failed to get im0: {e}")
                break

        return "Module"

    def _get_subslot_details(
        self,
        con,
        slot: int,
        subslot: int,
        module_id: int,
    ) -> str:
        """Get details string for a subslot."""
        if not con:
            return ""

        parts = []

        # Interface subslot - show station name and IP
        if slot == 0 and subslot == 0x8000:
            try:
                pd_real = con.read_pd_real_data()
                if pd_real.interface:
                    parts.append(pd_real.interface.chassis_id)
                    parts.append(f"IP:{pd_real.interface.ip_str}")
            except Exception as e:
                self.logger.debug(f"Failed to get pd_real: {e}")
            return " ".join(parts) if parts else ""

        # Port subslots - show link state and peer
        if 0x8001 <= subslot <= 0x800F:
            try:
                from ..helpers import get_blocks_module, get_indices_module

                pn_indices = get_indices_module()
                result = con.read(
                    api=0,
                    slot=slot,
                    subslot=subslot,
                    idx=pn_indices.PD_PORT_DATA_REAL,
                )
                if result and result.payload:
                    pn_blocks = get_blocks_module()
                    port = pn_blocks.parse_pd_port_data_real(
                        result.payload[6:], slot=slot, subslot=subslot
                    )
                    link = (
                        "Up"
                        if port.link_state_link == 1
                        else "Down"
                        if port.link_state_link == 2
                        else "Testing"
                    )
                    parts.append(link)
                    if port.mau_type_name and port.mau_type_name != "Unknown":
                        parts.append(port.mau_type_name)
                    if port.peers and port.peers[0].chassis_id:
                        peer = port.peers[0]
                        parts.append(f"-> {peer.chassis_id}:{peer.port_id}")
            except Exception as e:
                self.logger.debug(f"Optional import get_indices_module not available: {e}")
            return " ".join(parts) if parts else ""

        # Regular subslots - show I&M0 info
        if subslot == 1:
            try:
                im0 = con.read_im0(slot=slot, subslot=subslot)
                if im0:
                    vendor_id = (im0.vendor_id_high << 8) | im0.vendor_id_low
                    vendor = profinet_vendor_map.get(vendor_id, "")
                    if vendor:
                        parts.append(vendor)
                    order_id = (
                        im0.order_id.decode("ascii", errors="ignore").strip()
                        if isinstance(im0.order_id, bytes)
                        else str(im0.order_id).strip()
                    )
                    if order_id:
                        parts.append(order_id)
                    sw = (
                        f"v{im0.im_sw_revision_functional_enhancement}"
                        f".{im0.im_sw_revision_bug_fix}"
                        f".{im0.im_sw_revision_internal_change}"
                    )
                    parts.append(sw)
            except Exception as e:
                self.logger.debug(f"Failed to get im0: {e}")

        return " ".join(parts) if parts else ""

    def _get_slot_description(self, slot: int, subslot: int, module_id: int) -> str:
        """Get human-readable description for a slot/subslot."""
        if slot == 0:
            if subslot == 1:
                return "DAP"
            elif subslot == 0x8000:
                return "Interface"
            elif 0x8001 <= subslot <= 0x8004:
                return f"Port {subslot - 0x8000}"
            elif subslot >= 0x8000:
                return f"Port {subslot - 0x8000}"

        if subslot == 1:
            if module_id:
                if module_id & 0xF0000000 == 0x10000000:
                    return "I/O Module"
                elif module_id & 0xF0000000 == 0x20000000:
                    return "Comm Module"
                else:
                    return "Module"
            return "Module"
        elif subslot >= 0x8000:
            return f"Port {subslot - 0x8000}"

        return "Submodule"

    def _show_rpc_hint(self, device: Optional[ProfinetDevice] = None) -> None:
        """Show hint when RPC connection fails."""
        if (
            device
            and "IO-Controller" in device.device_roles
            and "IO-Device" not in device.device_roles
        ):
            self.logger.display(
                "  Hint: Device is IO-Controller only - needs I-Device mode for RPC"
            )
        else:
            self.logger.display(
                "  Hint: RPC access may require configuration - omit RPC flags for DCP only"
            )

    def _test_write_access(
        self,
        con,
        slot: int,
        subslot: int,
        idx: int,
        data: bytes,
    ) -> str:
        """Test if index is writable by writing the same value back.

        Returns: 'RW' if writable, 'RO' or error code if read-only/failed
        """
        try:
            con.write(api=0, slot=slot, subslot=subslot, idx=idx, data=data)
            return "RW"
        except Exception as e:
            err_str = str(e)
            if "0x" in err_str:
                import re

                match = re.search(r"(0x[0-9A-Fa-f]+)", err_str)
                if match:
                    return f"RO ({match.group(1)})"
            return "RO"

    # I&M indices known to be safe for write probing
    _SAFE_WRITE_PROBE_INDICES = range(0xAFF0, 0xAFF6)  # 0xAFF0-0xAFF5

    def _test_write_only(self, con, slot: int, subslot: int, idx: int) -> bool:
        """Test if an index that fails to read is write-only.

        Only probes known safe I&M indices (0xAFF0-0xAFF5) to avoid
        writing to unknown control/trigger registers.

        Returns: True if write-only, False otherwise
        """
        if idx not in self._SAFE_WRITE_PROBE_INDICES:
            return False
        try:
            con.write(
                api=0,
                slot=slot,
                subslot=subslot,
                idx=idx,
                data=b"\x00",
            )
            return True
        except Exception as e:
            self.logger.debug(f"con.write(: {e}")
            return False

    def _format_index_value(self, data: bytes) -> str:
        """Format index data as human-readable value."""
        size = len(data)
        if size == 0:
            return ""

        # W5: PROFINET uses big-endian byte order
        if size == 1:
            return f"{data[0]} (0x{data[0]:02X})"
        elif size == 2:
            val = int.from_bytes(data, "big")
            return f"{val} (0x{val:04X})"
        elif size == 4:
            val = int.from_bytes(data, "big")
            return f"{val} (0x{val:08X})"
        else:
            try:
                text = data.decode("utf-8", errors="ignore").rstrip("\x00").strip()
                if text and all(c.isprintable() or c.isspace() for c in text):
                    return f'"{text}"'
            except Exception as e:
                self.logger.debug(f"PROFINET RPC: failed to decode value as UTF-8 text: {e}")
        return ""

    def _get_index_data_type(self, idx: int) -> str:
        """Get data type hint for an index."""
        if idx in (0xAFF1, 0xAFF2, 0xAFF3, 0xAFF5):
            return "string"
        return "struct"
