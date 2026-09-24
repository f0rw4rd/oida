"""
PROFINET Enumeration Mixin

Handles index enumeration operations:
- Standard index enumeration
- Smart adaptive probing
- Full 0x0000-0xFFFF scan
- GSDML-based enumeration
- Custom range enumeration
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple, TYPE_CHECKING

from oida.utils.export_utils import export_table
from oida.protocols.profinet.models import ProfinetDevice

if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


class EnumerationMixin(_ScannerBase):
    """Mixin providing PROFINET index enumeration operations."""

    def _build_smart_probe_list(self, idx_module) -> List[Tuple[int, str]]:
        """Build smart probe list for efficient index enumeration.

        Strategy based on common vendor patterns:
        - Low indices (0-20): Device info/status
        - PROFIdrive/gateway indices: 47, 0x200F, 0xB02E
        - Channel-based patterns: N*100+0..10 for N=1..10
        - User range (0x0000-0x7FFF): Probe at 0x100 intervals + offsets 1-10
        - Subslot range (0x8000-0x80FF): Full scan (256 probes)
        - I&M range (0xAFF0-0xAFFF): Full scan (16 probes)
        - Slot range (0xC000-0xC0FF): Full scan (256 probes)
        - AR range (0xE000-0xE0FF): Full scan (256 probes)
        - API/Device range (0xF000-0xFFFF): Full scan (4096 probes)

        Total: ~6000 probes instead of 65536 (11x faster)
        """
        probe_set: set = set()

        # Include all known standard indices first
        for idx, _name in idx_module.ALL_STANDARD_INDICES:
            probe_set.add(idx)

        # Low indices (0-20) - common for device info/status
        for i in range(21):
            probe_set.add(i)

        # PROFIdrive Data Set 47
        probe_set.add(47)

        # Special gateway indices
        probe_set.add(0x200F)  # Beckhoff CoE gateway
        probe_set.add(0xB02E)  # ABB PROFIdrive PNU access

        # Channel-based patterns: N*100 + offset for N=1..10
        for channel in range(1, 11):
            base = channel * 100
            for offset in range(11):
                probe_set.add(base + offset)

        # User/manufacturer range: probe at 0x100 intervals + small offsets
        for base in range(0x0000, 0x8000, 0x100):
            probe_set.add(base)
            for offset in range(1, 11):
                probe_set.add(base + offset)

        # Subslot-specific range (0x8000-0x80FF) - full scan
        for i in range(0x8000, 0x8100):
            probe_set.add(i)

        # I&M range (0xAFF0-0xAFFF) - full scan
        for i in range(0xAFF0, 0xB000):
            probe_set.add(i)

        # Slot-specific range (0xC000-0xC0FF) - full scan
        for i in range(0xC000, 0xC100):
            probe_set.add(i)

        # AR-specific range (0xE000-0xE0FF) - full scan
        for i in range(0xE000, 0xE100):
            probe_set.add(i)

        # API/Device range (0xF000-0xFFFF) - full scan
        for i in range(0xF000, 0x10000):
            probe_set.add(i)

        # Convert set to sorted list with names
        return [(i, idx_module.get_index_name(i)) for i in sorted(probe_set)]

    def _get_enum_options(self) -> Dict:
        """Extract enumeration options from args."""
        return {
            "enum_all": self._arg("enum_all", False),
            "enum_smart": self._arg("enum_smart", False),
            "enum_range": self._arg("enum_range", None),
            "show_data": self._arg("show_data", False),
            "test_write": self._arg("test_write", False),
            "detect_write_only": self._arg("detect_write_only", False),
            "slot_arg": self._arg("slot", None),
        }

    def _filter_slots(
        self,
        discovered_slots: Optional[list],
        filter_slot: Optional[int],
        filter_subslot: Optional[int],
    ) -> List[Tuple[int, int]]:
        """Filter slots based on slot/subslot arguments."""
        if discovered_slots is None:
            discovered_slots = [(0, 1, 0, 0)]

        slots_to_scan = []
        for slot, subslot, _mod_id, _submod_id in discovered_slots:
            if filter_slot is not None and slot != filter_slot:
                continue
            if filter_subslot is not None and subslot != filter_subslot:
                continue
            slots_to_scan.append((slot, subslot))
        return slots_to_scan

    def _build_probe_list(
        self,
        idx_module,
        options: dict,
        use_gsdml: bool,
    ) -> Optional[List[Tuple[int, str]]]:
        """Build list of indices to probe based on enumeration options."""
        if use_gsdml:
            probe_list = self._gsdml.get_all_indices()
            self.logger.display(f"  GSDML defines {len(probe_list)} indices")
            return probe_list

        if options["enum_range"]:
            try:
                parts = options["enum_range"].split("-")
                start = int(parts[0], 0)
                end = int(parts[1], 0) if len(parts) > 1 else start
                if start > end:
                    self.logger.fail(
                        f"  Invalid range: start 0x{start:04X} > end 0x{end:04X} "
                        f"({options['enum_range']})"
                    )
                    return None
                return [(i, idx_module.get_index_name(i)) for i in range(start, end + 1)]
            except ValueError:
                self.logger.fail(f"  Invalid range format: {options['enum_range']}")
                return None

        if options["enum_all"]:
            return [(i, idx_module.get_index_name(i)) for i in range(0x10000)]

        if options["enum_smart"]:
            return self._build_smart_probe_list(idx_module)

        # Default: standard indices + common user-range indices
        probe_list = list(idx_module.ALL_STANDARD_INDICES)
        for i in range(21):
            probe_list.append((i, f"User-specific (0x{i:04X})"))
        for channel in range(1, 33):
            for param in range(1, 7):
                idx = channel * 100 + param
                probe_list.append((idx, f"Channel {channel} Param {param}"))
        return probe_list

    def _deduplicate_probe_list(self, probe_list: List[Tuple[int, str]]) -> List[Tuple[int, str]]:
        """Remove duplicate indices from probe list."""
        seen: set = set()
        unique_list = []
        for idx, name in probe_list:
            if idx not in seen:
                seen.add(idx)
                unique_list.append((idx, name))
        return unique_list

    def _probe_slot(
        self,
        con,
        slot: int,
        subslot: int,
        unique_list: list,
        idx_module,
        options: dict,
        access_stats: dict,
    ) -> Tuple[list, list, dict, int]:
        """Probe a single slot/subslot for readable indices."""
        import time as _time

        all_readable: list = []
        failed_reads: list = []
        results: dict = {}

        adaptive_mode = options["enum_smart"]
        adaptive_range = 10
        probed_this_slot: set = set()
        pending_probes = list(unique_list)
        total_ops = len(unique_list)
        op_count = 0
        last_progress_time = 0.0

        while pending_probes:
            idx, name = pending_probes.pop(0)

            if idx in probed_this_slot:
                continue
            probed_this_slot.add(idx)

            op_count += 1
            now = _time.monotonic()
            if now - last_progress_time >= 0.25 or op_count == total_ops:
                self.logger.progress(
                    op_count,
                    total_ops,
                    len(all_readable),
                    op_count - len(all_readable),
                )
                last_progress_time = now

            read_success = False
            try:
                result = con.read(api=0, slot=slot, subslot=subslot, idx=idx)
                if result and len(result.payload) > 0:
                    read_success = True
                    data = result.payload

                    if options["test_write"]:
                        access = self._test_write_access(con, slot, subslot, idx, data)
                        access_stats[access] = access_stats.get(access, 0) + 1
                    else:
                        access = "R"

                    key = (slot, subslot, idx)
                    results[key] = {
                        "status": "readable",
                        "size": len(data),
                        "name": name,
                        "data": data,
                        "access": access,
                        "slot": slot,
                        "subslot": subslot,
                    }
                    all_readable.append((key, results[key]))

                    if adaptive_mode and idx < 0x8000:
                        for offset in range(1, adaptive_range + 1):
                            new_idx = idx + offset
                            if new_idx not in probed_this_slot and new_idx < 0x8000:
                                pending_probes.append(
                                    (
                                        new_idx,
                                        idx_module.get_index_name(new_idx),
                                    )
                                )
                                total_ops += 1
            except Exception as e:
                self.logger.debug(f"Operation failed: {e}")

            if not read_success and options["detect_write_only"]:
                failed_reads.append((idx, name))

        # Final progress update + newline to end the \r line
        self.logger.progress(
            op_count,
            total_ops,
            len(all_readable),
            op_count - len(all_readable),
            end="\n",
        )
        return all_readable, failed_reads, results, total_ops

    def _detect_write_only_indices(
        self,
        con,
        slot: int,
        subslot: int,
        failed_reads: list,
        access_stats: dict,
    ) -> list:
        """Test failed reads for write-only access."""
        write_only: list = []
        if not failed_reads:
            return write_only

        self.logger.display(f"  Testing {len(failed_reads)} failed reads for write-only...")
        for idx, name in failed_reads:
            if self._test_write_only(con, slot, subslot, idx):
                access_stats["W"] = access_stats.get("W", 0) + 1
                key = (slot, subslot, idx)
                write_only.append(
                    (
                        key,
                        {
                            "status": "write-only",
                            "size": 0,
                            "name": name,
                            "data": b"",
                            "access": "W",
                            "slot": slot,
                            "subslot": subslot,
                        },
                    )
                )
        return write_only

    def _build_table_data(self, all_indices: list, show_data: bool) -> List[list]:
        """Build table data rows from index results."""
        table_data = []
        for key, info in all_indices:
            slot, subslot, idx = key
            name = info.get("name", "Unknown")
            size = info.get("size", 0)
            access = info.get("access", "?")
            data = info.get("data", b"")

            subslot_str = f"0x{subslot:04X}" if subslot >= 0x8000 else str(subslot)
            row = [
                f"{slot}/{subslot_str}",
                f"0x{idx:04X}",
                name,
                str(size) if size > 0 else "-",
                access,
            ]

            if show_data:
                val_str = self._format_index_value(data) if data else "-"
                hex_preview = " ".join(f"{b:02X}" for b in data[:16]) if data else "-"
                if len(data) > 16:
                    hex_preview += "..."
                row.extend([val_str, hex_preview])

            table_data.append(row)
        return table_data

    def _display_results(
        self,
        table_data: list,
        all_readable: list,
        write_only_indices: list,
        access_stats: dict,
        options: dict,
        total_ops: int,
    ) -> None:
        """Display enumeration results as a table."""
        if options["test_write"] or options["detect_write_only"]:
            parts = [f"{len(all_readable)} readable"]
            if access_stats.get("RO", 0) > 0:
                parts.append(f"{access_stats.get('RO', 0)} RO")
            if access_stats.get("RW", 0) > 0:
                parts.append(f"{access_stats.get('RW', 0)} RW")
            if access_stats.get("W", 0) > 0:
                parts.append(f"{access_stats.get('W', 0)} write-only")
            self.logger.display(f"  Found: {', '.join(parts)}")
        else:
            self.logger.display(f"  Found {len(all_readable)} readable out of {total_ops} tested")

        if not table_data:
            return

        headers = ["Slot/Sub", "Index", "Name", "Size", "Access"]
        if options["show_data"]:
            headers.extend(["Value", "Data"])

        title_parts = [f"{len(all_readable)} readable"]
        if write_only_indices:
            title_parts.append(f"{len(write_only_indices)} write-only")

        # W8: Use export_table for --output support
        export_table(
            "profinet_indices",
            headers,
            table_data,
            title=(f"PROFINET Record Indices ({', '.join(title_parts)})"),
        )

        if options["test_write"] or options["detect_write_only"]:
            legend = "  Legend: R=Readable, RO=Read-Only, RW=Read-Write"
            if options["detect_write_only"]:
                legend += ", W=Write-Only"
            self.logger.display(legend)
        else:
            self.logger.display("  Legend: R=Readable (use --test-write to check write access)")

    def _display_hex_dumps(self, all_readable: list) -> None:
        """Display full hex dumps of readable indices."""
        self.logger.display("")
        for key, info in sorted(all_readable):
            slot, subslot, idx = key
            name = info.get("name", "Unknown")
            size = info.get("size", 0)
            data = info.get("data", b"")
            subslot_str = f"0x{subslot:04X}" if subslot >= 0x8000 else str(subslot)

            self.logger.display(f"  [{slot}/{subslot_str}] 0x{idx:04X} {name} ({size} bytes):")
            for j in range(0, len(data), 32):
                chunk = data[j : j + 32]
                hex_str = " ".join(f"{b:02X}" for b in chunk)
                ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
                self.logger.display(f"    {hex_str}  {ascii_str}")

    def _enumerate_indices(
        self,
        device: ProfinetDevice,
        con,
        discovered_slots: Optional[list] = None,
    ) -> None:
        """Enumerate available record indices with table display."""
        options = self._get_enum_options()
        try:
            filter_slot, filter_subslot = self._parse_slot_arg(options["slot_arg"])
        except ValueError as e:
            self.logger.fail(f"  {e}")
            return

        # Safety checks for write operations
        if options["test_write"] and not self._arg("confirm", False):
            self.logger.fail("--test-write requires --confirm flag (performs write operations)")
            return
        if options["detect_write_only"] and not self._arg("confirm", False):
            self.logger.fail(
                "--detect-write-only requires --confirm flag (performs write operations)"
            )
            return

        # Filter slots
        slots_to_scan = self._filter_slots(discovered_slots, filter_slot, filter_subslot)
        if not slots_to_scan:
            self.logger.fail(f"  No matching slots found for --slot {options['slot_arg']}")
            return

        # Check GSDML match
        use_gsdml = False
        if self._gsdml:
            if (
                self._gsdml.vendor_id == device.vendor_id
                and self._gsdml.device_id == device.device_id
            ):
                use_gsdml = True
                self.logger.display(
                    f"  Using GSDML indices for"
                    f" {self._gsdml.vendor_name}"
                    f" (0x{self._gsdml.device_id:04X})"
                )
            else:
                self.logger.display(
                    f"  GSDML mismatch:"
                    f" file=0x{self._gsdml.device_id:04X},"
                    f" device=0x{device.device_id:04X}"
                )

        self.logger.display(
            f"  Enumerating record indices on {len(slots_to_scan)} slot/subslot(s)..."
        )

        try:
            from oida.protocols.profinet.helpers import get_indices_module

            idx_module = get_indices_module()

            # Build probe list
            probe_list = self._build_probe_list(idx_module, options, use_gsdml)
            if probe_list is None:
                return
            unique_list = self._deduplicate_probe_list(probe_list)

            # Enumerate all slots
            all_readable: list = []
            write_only_indices: list = []
            access_stats: Dict[str, int] = {"RO": 0, "RW": 0, "W": 0}
            total_ops = 0

            for slot, subslot in slots_to_scan:
                readable, failed, _results, ops = self._probe_slot(
                    con,
                    slot,
                    subslot,
                    unique_list,
                    idx_module,
                    options,
                    access_stats,
                )
                all_readable.extend(readable)
                total_ops += ops

                if options["detect_write_only"]:
                    wo = self._detect_write_only_indices(con, slot, subslot, failed, access_stats)
                    write_only_indices.extend(wo)

            self.logger.display("")

            if all_readable or write_only_indices:
                # Real record reads/writes succeeded: a genuine PROFINET device.
                self._profinet_response_seen = True

            # Build and display results
            all_indices = sorted(all_readable + write_only_indices)
            table_data = self._build_table_data(all_indices, options["show_data"])
            self._display_results(
                table_data,
                all_readable,
                write_only_indices,
                access_stats,
                options,
                total_ops,
            )

            if options["show_data"]:
                self._display_hex_dumps(all_readable)

        except Exception as e:
            self.logger.debug(f"Failed to enumerate indices: {e}")
