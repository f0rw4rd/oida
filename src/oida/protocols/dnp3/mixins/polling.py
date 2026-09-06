"""
DNP3 Polling Mixin (opendnp3 / yadnp3)

Handles data polling and enumeration operations:
- Integrity polling (Class 0/1/2/3)
- Class-specific reads
- Specific group/variation reads
- Device attribute reads (Group 0)
- Data collection from ISOEHandler
- Point enumeration from device attributes
- Probing supported DNP3 groups
- Security statistics (Group 121)
"""

from __future__ import annotations

import re as _re
from typing import Any, Dict, TYPE_CHECKING

from ..constants import (
    KNOWN_ATTRIBUTES,
    SECURITY_RELEVANT_ATTRS,
    SECURITY_RELEVANT_ATTR_IDS,
    DNP3_GROUP_NAMES,
    _decode_flags,
)
from ....utils import ProgressTracker
from ....utils.export_utils import export_table
from ....utils.export_utils import configure as configure_export

if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


# Handler attribute -> result key mapping for _collect_data.
_DATA_TYPES = (
    ("binary_inputs", "binary_inputs"),
    ("double_bit_binary_inputs", "double_bit_binary_inputs"),
    ("binary_output_statuses", "binary_output_statuses"),
    ("counters", "counters"),
    ("frozen_counters", "frozen_counters"),
    ("analog_inputs", "analog_inputs"),
    ("analog_output_statuses", "analog_output_statuses"),
)


class PollingMixin(_ScannerBase):
    """Mixin providing DNP3 polling and data enumeration operations."""

    def _perform_integrity_poll(self, results: Dict[str, Any]) -> None:
        """Perform an integrity poll (Class 0/1/2/3)."""
        if not self._connected or not self._handler or not self._master:
            self.logger.debug("Not connected - skipping integrity poll")
            results["operations"] = results.get("operations", {})
            results["operations"]["integrity_poll"] = {"success": False, "error": "Not connected"}
            return

        self.logger.debug("Performing integrity poll (Class 0/1/2/3)...")
        self._handler.clear()

        try:
            dnp3 = self._dnp3
            class_field = dnp3.ClassField.AllClasses()

            result = self._sync_scan(
                lambda master, handler, config: master.ScanClasses(class_field, handler, config)
            )

            if result:
                self._collect_data(results)
                bi_count = len(self._handler.binary_inputs)
                ai_count = len(self._handler.analog_inputs)
                ct_count = len(self._handler.counters)
                bo_count = len(self._handler.binary_output_statuses)
                ao_count = len(self._handler.analog_output_statuses)
                # Build compact point summary, only showing types with data
                parts = []
                if bi_count:
                    parts.append(f"{bi_count} BI")
                if ai_count:
                    parts.append(f"{ai_count} AI")
                if ct_count:
                    parts.append(f"{ct_count} CT")
                if bo_count:
                    parts.append(f"{bo_count} BO")
                if ao_count:
                    parts.append(f"{ao_count} AO")
                dbbi_count = len(self._handler.double_bit_binary_inputs)
                fct_count = len(self._handler.frozen_counters)
                oct_count = len(self._handler.octet_strings)
                if dbbi_count:
                    parts.append(f"{dbbi_count} DBBI")
                if fct_count:
                    parts.append(f"{fct_count} FCT")
                if oct_count:
                    parts.append(f"{oct_count} Octet")
                self.logger.display(f"Points: {', '.join(parts)}" if parts else "Points: none")

                # Log group details at debug level
                groups_found = []
                if self._handler.binary_inputs:
                    groups_found.append("Group 1 (BI)")
                if self._handler.double_bit_binary_inputs:
                    groups_found.append("Group 3 (DBBI)")
                if self._handler.binary_output_statuses:
                    groups_found.append("Group 10 (BO)")
                if self._handler.counters:
                    groups_found.append("Group 20 (CT)")
                if self._handler.frozen_counters:
                    groups_found.append("Group 21 (FCT)")
                if self._handler.analog_inputs:
                    groups_found.append("Group 30 (AI)")
                if self._handler.analog_output_statuses:
                    groups_found.append("Group 40 (AO)")
                if self._handler.octet_strings:
                    groups_found.append("Group 110 (Octet)")
                if groups_found:
                    self.logger.debug(f"Groups in response: {', '.join(groups_found)}")
            else:
                reason = self._error_detail()
                self.logger.warning(f"Integrity poll failed ({reason})")
                results.setdefault("operations", {})["integrity_poll"] = {
                    "success": False,
                    "error": reason,
                }
                # A timeout almost always means we are polling the wrong link
                # address. Point the operator at address enumeration.
                if "timeout" in reason:
                    self.logger.display(
                        "Wrong link address? Enumerate with --scan-range 0-15 "
                        "or set --outstation-addr <n>"
                    )

        except Exception as e:
            self.logger.fail(f"Integrity poll error: {type(e).__name__}: {e}")
            results.setdefault("operations", {})["integrity_poll"] = {
                "success": False,
                "error": str(e),
            }

    def _perform_class_read(self, results: Dict[str, Any], class_str: str) -> None:
        """Perform a class-specific read."""
        if not self._connected or not self._handler or not self._master:
            return

        dnp3 = self._dnp3
        class_num = int(class_str)
        self.logger.debug(f"Reading Class {class_num} data...")
        self._handler.clear()

        # Build ClassField for the specific class
        flags = [False, False, False, False]  # class 0, 1, 2, 3
        if 0 <= class_num <= 3:
            flags[class_num] = True
        class_field = dnp3.ClassField(*flags)

        try:
            result = self._sync_scan(
                lambda master, handler, config: master.ScanClasses(class_field, handler, config)
            )

            if result:
                self._collect_data(results, prefix=f"class{class_num}")
                self.logger.display(f"Class {class_num} read completed")
            else:
                reason = self._error_detail()
                self.logger.warning(f"Class {class_num} read failed ({reason})")

        except Exception as e:
            self.logger.fail(f"Class {class_num} read error: {type(e).__name__}: {e}")

    def _perform_variation_read(self, results: Dict[str, Any], variation_str: str) -> None:
        """Perform a specific group/variation read (e.g., '30.0' for Group 30 Var 0)."""
        if not self._connected or not self._handler or not self._master:
            return

        try:
            dnp3 = self._dnp3

            parts = variation_str.split(".")
            group = int(parts[0])
            var = int(parts[1]) if len(parts) > 1 else 0
            var_name = f"Group{group}Var{var}"

            self._handler.clear()

            gv_id = dnp3.GroupVariationID(group, var)
            result = self._sync_scan(
                lambda master, handler, config, _gv=gv_id: master.ScanAllObjects(
                    _gv, handler, config
                )
            )

            if result:
                self._collect_data(results, prefix=f"g{group}v{var}")
                self.logger.display(f"Read {var_name} completed")
            else:
                reason = self._error_detail()
                self.logger.warning(f"Read {var_name} failed ({reason})")

        except Exception as e:
            self.logger.fail(f"Variation read error: {type(e).__name__}: {e}")

    def _read_device_attributes(self, results: Dict[str, Any]) -> None:
        """Read device attributes (Group 0)."""
        if not self._connected or not self._handler or not self._master:
            return

        self.logger.debug("Reading device attributes (Group 0)...")
        self._handler.clear()

        try:
            dnp3 = self._dnp3

            # Read Group 0 Var 254 (all attributes request)
            gv_id = dnp3.GroupVariationID(0, 254)
            result = self._sync_scan(
                lambda master, handler, config: master.ScanAllObjects(gv_id, handler, config)
            )

            if result and self._handler.string_attrs:
                attrs = {}
                show_all = getattr(self, "device_attributes", False)

                # Collect all attributes into attrs dict and a var_num lookup
                by_var = {}
                for attr in self._handler.string_attrs:
                    var_num = attr.get("variation", 0)
                    name = KNOWN_ATTRIBUTES.get(var_num, f"Attribute_{var_num}")
                    value = attr.get("value", "")
                    attrs[name] = {
                        "variation": var_num,
                        "set": attr.get("set", 0),
                        "value": value,
                    }
                    by_var[var_num] = (name, value)

                def _val(var_num):
                    """Return attribute value if present and non-empty, else None."""
                    if var_num in by_var:
                        v = by_var[var_num][1]
                        if v and str(v).strip():
                            return str(v).strip()
                    return None

                # Emit one "tag: value" per line, in attribute order:
                # product/identity, then version/serial, then identity/location.
                labelled = [
                    ("Product", _val(252)),
                    ("Vendor", _val(254)),
                    ("Conformance", _val(250)),
                    ("SW", _val(242)),
                    ("HW", _val(243)),
                    ("Serial", _val(249)),
                    ("Device", _val(247)),
                    ("Owner", _val(248)),
                    ("Location", _val(245)),
                    ("ID", _val(246)),
                ]
                if _val(252) and not _val(254):
                    self.logger.debug("Vendor attribute not provided by outstation")
                present = [(label, value) for label, value in labelled if value]
                if present:
                    self.logger.display("Device Information")
                    for label, value in present:
                        self.logger.display(f"  {label}: {value}")

                for var_num, label in SECURITY_RELEVANT_ATTRS:
                    if var_num in by_var:
                        _, value = by_var[var_num]
                        self.logger.debug(f"Attr {label}: {value}")

                for var_num, (name, value) in by_var.items():
                    if var_num in SECURITY_RELEVANT_ATTR_IDS:
                        continue
                    if show_all:
                        self.logger.display(f"    {name}: {value}")
                    else:
                        self.logger.debug(f"  Attr [{var_num}] {name}: {value}")

                results["device_attributes"] = attrs
            elif not result:
                reason = self._error_detail()
                self.logger.display(
                    f"  No device attributes returned by outstation (read request failed: {reason})"
                )
            else:
                self.logger.display(
                    "  No device attributes returned by outstation "
                    "(read succeeded but response contained no string attributes)"
                )

        except Exception as e:
            self.logger.fail(f"Device attribute read error: {type(e).__name__}: {e}")

    def _collect_data(self, results: Dict[str, Any], prefix: str = "integrity") -> None:
        """Collect data from the ISOEHandler into results."""
        data_key = f"data_points_{prefix}" if prefix != "integrity" else "data_points"

        data = {}

        for handler_attr, result_key in _DATA_TYPES:
            items = getattr(self._handler, handler_attr, [])
            if items:
                data[result_key] = []
                for pt in items:
                    val_obj = pt.value
                    raw_value = getattr(val_obj, "value", val_obj)
                    if hasattr(raw_value, "value") and not isinstance(
                        raw_value, (int, float, str, bool)
                    ):
                        raw_value = int(raw_value)
                    flags = getattr(val_obj, "flags", None)
                    flags_val = getattr(flags, "value", 0) if flags else 0
                    online = bool(flags_val & 0x01)
                    data[result_key].append(
                        {
                            "index": pt.index,
                            "value": raw_value,
                            "flags": flags_val,
                            "online": online,
                        }
                    )

        # IIN data from the master application
        iin = getattr(self._app, "iin", None) if self._app else None
        if iin is not None:
            dnp3 = self._dnp3
            iin_data = {}
            for bit_name in (
                "BROADCAST",
                "CLASS1_EVENTS",
                "CLASS2_EVENTS",
                "CLASS3_EVENTS",
                "NEED_TIME",
                "LOCAL_CONTROL",
                "DEVICE_TROUBLE",
                "DEVICE_RESTART",
                "FUNC_NOT_SUPPORTED",
                "OBJECT_UNKNOWN",
                "PARAM_ERROR",
                "EVENT_BUFFER_OVERFLOW",
                "CONFIG_CORRUPT",
            ):
                bit = getattr(dnp3.IINBit, bit_name, None)
                if bit is not None:
                    iin_data[bit_name.lower()] = iin.IsSet(bit)
            results["iin"] = iin_data

        results[data_key] = data

    def _enumerate_points(self, results: Dict[str, Any]) -> None:
        """Enumerate all data points from device attributes and integrity poll."""
        self.logger.debug("Enumerating data points from device attributes...")

        configure_export(
            output_dir=getattr(self, "output_dir", None),
            logger=self.logger,
        )

        if "device_attributes" not in results or not results["device_attributes"]:
            self._read_device_attributes(results)

        attrs = results.get("device_attributes", {})
        point_info = {}

        point_types = [
            (
                "Number of Binary Inputs",
                "Max Binary Input Index",
                "binary_inputs",
                "binary_inputs",
                "Binary Inputs (BI)",
            ),
            (
                "Number of Double-Bit BIs",
                "Max Double-Bit BI Index",
                "double_bit_binary_inputs",
                "double_bit_binary_inputs",
                "Double-Bit BI (DBI)",
            ),
            (
                "Number of Binary Outputs",
                "Max Binary Output Index",
                "binary_outputs",
                "binary_output_statuses",
                "Binary Outputs (BO)",
            ),
            (
                "Number of Counter Points",
                "Max Counter Index",
                "counters",
                "counters",
                "Counters (CT)",
            ),
            (
                "Number of Frozen Counters",
                "Max Frozen Counter Index",
                "frozen_counters",
                "frozen_counters",
                "Frozen Counters (FC)",
            ),
            (
                "Number of Analog Inputs",
                "Max Analog Input Index",
                "analog_inputs",
                "analog_inputs",
                "Analog Inputs (AI)",
            ),
            (
                "Number of Analog Outputs",
                "Max Analog Output Index",
                "analog_outputs",
                "analog_output_statuses",
                "Analog Outputs (AO)",
            ),
        ]

        for count_attr, max_attr, attr_key, _data_key, _label in point_types:
            count = 0
            max_index = None

            if count_attr in attrs:
                count_val = attrs[count_attr].get("value", "")
                try:
                    count = int(count_val)
                except (ValueError, TypeError) as e:
                    self.logger.debug(f"Failed to get count: {e}")

            if max_attr in attrs:
                max_val = attrs[max_attr].get("value", "")
                try:
                    max_index = int(max_val)
                except (ValueError, TypeError) as e:
                    self.logger.debug(f"Failed to get max_index: {e}")

            if count > 0 or max_index is not None:
                point_info[attr_key] = {
                    "count": count,
                    "max_index": max_index,
                    "range": f"0-{max_index}" if max_index is not None else f"0-{count - 1}",
                }

        data_points = results.get("data_points", {})
        host_suffix = self.host.replace(".", "_")
        has_any = any(
            isinstance(data_points.get(dk, []), list) and data_points.get(dk)
            for *_, dk, _ in point_types
        )

        if has_any:
            self.logger.display(
                "Flags: ON=Online RST=Restart CL=CommLost "
                "RF=RemoteForced LF=LocalForced OR=OverRange RE=RefErr ST=State"
            )

        for _ca, _ma, attr_key, data_key, label in point_types:
            items = data_points.get(data_key, [])
            if not isinstance(items, list) or not items:
                continue

            by_index = {}
            for p in items:
                by_index[p.get("index", 0)] = p
            sorted_items = sorted(by_index.values(), key=lambda p: p.get("index", 0))

            indices = list(by_index.keys())
            if attr_key not in point_info:
                point_info[attr_key] = {}
            point_info[attr_key]["observed_count"] = len(sorted_items)
            point_info[attr_key]["observed_range"] = f"{min(indices)}-{max(indices)}"

            headers = ["Index", "Value", "Flags"]
            rows = []
            for p in sorted_items:
                val = p.get("value", "?")
                if isinstance(val, float):
                    val = f"{val:.4f}"
                rows.append(
                    [
                        p.get("index", "?"),
                        val,
                        _decode_flags(p.get("flags", 0)),
                    ]
                )

            table_name = f"dnp3_{data_key}_{host_suffix}"
            export_table(table_name, headers, rows, title=label)

        if not has_any:
            self.logger.display("Point enumeration: no point values available")

        results["operations"]["enumerate_points"] = {
            "success": True,
            "points": point_info,
        }

    def _probe_supported_groups(self, results: Dict[str, Any]) -> None:
        """Probe all DNP3 groups 0-122 to discover supported objects."""
        dnp3 = self._dnp3

        if not self._connected or not self._handler or not self._master:
            self.logger.debug("Not connected - skipping probe")
            return

        self.logger.display("Probing supported DNP3 groups (0-122)...")

        group_variations = {}
        # opendnp3.GroupVariation is a pybind11 enum and is not directly
        # iterable (raises TypeError); iterate its __members__ instead.
        for member in dnp3.GroupVariation.__members__.values():
            match = _re.match(r"Group(\d+)Var(\d+)$", member.name)
            if not match:
                continue
            grp = int(match.group(1))
            var = int(match.group(2))
            if grp not in group_variations:
                group_variations[grp] = (var, member)
            else:
                existing_var = group_variations[grp][0]
                if var == 0:
                    group_variations[grp] = (var, member)
                elif existing_var > 0 and var < existing_var:
                    group_variations[grp] = (var, member)

        supported = []
        failed = []
        consecutive_failures = 0
        max_consecutive_failures = 10
        total = 123
        progress = ProgressTracker(total, logger=self.logger, show=True)

        for grp in range(0, 123):
            progress.update()

            if grp not in group_variations:
                self.logger.debug(f"Group {grp}: no GroupVariation enum, skipping")
                continue

            var_num = group_variations[grp][0]
            self._handler.clear()

            try:
                gv_id = dnp3.GroupVariationID(grp, var_num)
                result = self._sync_scan(
                    lambda master, handler, config, _gv=gv_id: master.ScanAllObjects(
                        _gv, handler, config
                    ),
                    timeout=2.0,
                )

                if result:
                    consecutive_failures = 0
                    point_count = (
                        len(self._handler.binary_inputs)
                        + len(self._handler.double_bit_binary_inputs)
                        + len(self._handler.binary_output_statuses)
                        + len(self._handler.counters)
                        + len(self._handler.frozen_counters)
                        + len(self._handler.analog_inputs)
                        + len(self._handler.analog_output_statuses)
                        + len(self._handler.octet_strings)
                        + len(self._handler.security_stats)
                    )
                    supported.append(
                        {
                            "group": grp,
                            "name": DNP3_GROUP_NAMES.get(grp, f"Group {grp}"),
                            "points": point_count,
                            "responded": True,
                        }
                    )
                    self.logger.debug(f"Group {grp}: supported ({point_count} points)")
                else:
                    consecutive_failures += 1
                    reason = self._error_detail()
                    failed.append({"group": grp, "error": reason})
                    self.logger.debug(f"Group {grp}: failed ({reason})")
            except Exception as e:
                consecutive_failures += 1
                failed.append({"group": grp, "error": str(e)})
                self.logger.debug(f"Group {grp}: exception {e}")

            if consecutive_failures >= max_consecutive_failures and not supported:
                self.logger.warning(
                    f"Outstation not responding ({consecutive_failures} consecutive failures), aborting probe"
                )
                break

        if supported:
            self.logger.display("Supported groups (probe):")
            for entry in supported:
                grp = entry["group"]
                name = entry["name"]
                pts = entry["points"]
                pts_str = f"{pts} points" if pts > 0 else "responded"
                self.logger.display(f"  Group {grp:<4d} {name:<28s} {pts_str}")
        else:
            self.logger.display("No groups responded to probe")

        if self.debug and failed:
            self.logger.debug(f"{len(failed)} groups did not respond")

        results["operations"]["probe_objects"] = {
            "success": True,
            "supported": supported,
            "total_probed": total,
            "total_supported": len(supported),
        }

    def _read_security_stats(self, results: Dict[str, Any]) -> None:
        """Read Security Statistics (Group 121) from the outstation."""
        dnp3 = self._dnp3

        if not self._connected or not self._handler or not self._master:
            self.logger.debug("Not connected - skipping security stats")
            return

        self.logger.debug("Reading security statistics (Group 121)...")
        self._handler.clear()

        try:
            gv_id = dnp3.GroupVariationID(121, 0)

            result = self._sync_scan(
                lambda master, handler, config: master.ScanAllObjects(gv_id, handler, config)
            )

            if result:
                stats = []
                for item in self._handler.security_stats:
                    val_obj = item.value
                    stat_val = getattr(val_obj, "value", None)
                    stats.append(
                        {
                            "index": item.index,
                            "value": getattr(stat_val, "count", 0) if stat_val else 0,
                            "flags": getattr(getattr(val_obj, "quality", None), "value", 0),
                        }
                    )

                if not stats:
                    for item in self._handler.counters:
                        val_obj = item.value
                        stats.append(
                            {
                                "index": item.index,
                                "value": getattr(val_obj, "value", 0),
                                "flags": getattr(getattr(val_obj, "flags", None), "value", 0),
                            }
                        )

                if stats:
                    self.logger.display(f"Security statistics: {len(stats)} counters")
                    for s in stats:
                        self.logger.display(f"  Stat[{s['index']}]: {s['value']}")
                else:
                    self.logger.display("Security statistics: read succeeded but no data returned")

                results["operations"]["security_stats"] = {
                    "success": True,
                    "stats": stats,
                    "count": len(stats),
                }
            else:
                reason = self._error_detail()
                self.logger.display(f"Security statistics not available ({reason})")
                results["operations"]["security_stats"] = {
                    "success": False,
                    "error": reason,
                }

        except Exception as e:
            self.logger.fail(f"Security statistics error: {type(e).__name__}: {e}")
            results["operations"]["security_stats"] = {
                "success": False,
                "error": str(e),
            }
