"""
EtherNet/IP Controller Info Mixin

Handles controller-specific information retrieval:
- Controller mode interpretation (keyswitch, run/prog/rem)
- Controller time and clock drift detection
- Tag database analysis (counts, scoping, arrays, external access)
- Tag dump/export
- Data type enumeration (UDTs, AOIs)
- Tag read operations (single, batch, full list)
- Dangerous tag identification
- Device identity/info via tags
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, TYPE_CHECKING

from oida.protocols.ethernetip.attacks import DANGEROUS_TAG_PATTERNS

if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


class ControllerInfoMixin(_ScannerBase):
    """Mixin providing controller information and tag operations."""

    def _interpret_controller_mode(self, conn: Any) -> Dict[str, Any]:
        """
        Interpret controller mode from pycomm3 LogixDriver conn.info.

        Returns controller mode information including:
        - keyswitch: Physical keyswitch position (RUN/PROG/REM)
        - mode: Controller operating mode
        - is_editable: True if PLC program can be modified
        - is_remote: True if mode can be changed remotely
        """
        result = {
            "keyswitch": None,
            "mode": "Unknown",
            "is_editable": False,
            "is_remote": False,
            "is_faulted": False,
        }

        if self._driver_type != "logix" or not hasattr(conn, "info"):
            return result

        try:
            info = conn.info
            if not info:
                return result

            # Get keyswitch from pycomm3 LogixDriver info
            keyswitch = info.get("keyswitch", "").upper()
            result["keyswitch"] = keyswitch

            # Interpret keyswitch positions for ControlLogix/CompactLogix
            # Possible values: RUN, PROG, REM (REMOTE)
            # Remote mode can be: REMOTE RUN, REMOTE PROG, REMOTE TEST
            if keyswitch:
                result["mode"] = keyswitch

                # Check if controller is in a mode that allows editing
                if "PROG" in keyswitch:
                    result["is_editable"] = True
                elif "TEST" in keyswitch:
                    result["is_editable"] = True

                # Check if mode can be changed remotely (REMOTE keyswitch position)
                if "REMOTE" in keyswitch or "REM" in keyswitch:
                    result["is_remote"] = True

            # Check for fault status from status field
            status = info.get("status", 0)
            if isinstance(status, int):
                # Status word bit interpretation (ControlLogix)
                # Bits 0-3: Owned/Configured/Extended1/Extended2
                # Bits 4-7: Minor Recoverable/Minor Unrecoverable/Major Recoverable/Major Unrecoverable
                if status & 0xF0:  # Any fault bits set
                    result["is_faulted"] = True

            # Log mode information
            if result["keyswitch"]:
                self.logger.display(f"  Mode: {result['mode']}")
                if result["is_editable"]:
                    self.logger.warning(f"  [!] Controller in editable mode ({result['mode']})")
                if result["is_remote"]:
                    self.logger.debug("Remote keyswitch - mode changeable via software")

        except Exception as e:
            self.logger.debug(f"Error interpreting controller mode: {e}")

        return result

    def _get_controller_time(self, conn: Any) -> Dict[str, Any]:
        """
        Get controller time using pycomm3 LogixDriver.

        Returns controller datetime and clock drift from system time.
        """
        result = {
            "controller_time": None,
            "system_time": None,
            "clock_drift_seconds": None,
        }

        if self._driver_type != "logix":
            return result

        try:
            import datetime

            # Get current system time (UTC-aware to match pycomm3's UTC PLC time)
            system_time = datetime.datetime.now(datetime.timezone.utc)
            result["system_time"] = system_time.isoformat()

            # Get PLC time using pycomm3
            if hasattr(conn, "get_plc_time"):
                plc_time_result = conn.get_plc_time()
                if plc_time_result and not plc_time_result.error:
                    # pycomm3 returns .value as a dict: {'datetime', 'microseconds',
                    # 'string'} — NOT a bare datetime. The old code called
                    # .isoformat() on the dict, which raised AttributeError that the
                    # except below swallowed, so controller_time was always None.
                    value = plc_time_result.value
                    plc_time = value.get("datetime") if isinstance(value, dict) else value
                    result["controller_time"] = plc_time.isoformat() if plc_time else None

                    # Calculate clock drift
                    if plc_time:
                        drift = abs((system_time - plc_time).total_seconds())
                        result["clock_drift_seconds"] = round(drift, 2)

                        # Log significant clock drift (> 60 seconds)
                        if drift > 60:
                            self.logger.warning(
                                f"  Clock drift: {drift:.1f} seconds "
                                f"(PLC: {plc_time.strftime('%H:%M:%S')}, "
                                f"System: {system_time.strftime('%H:%M:%S')})"
                            )
                        else:
                            self.logger.debug(f"Clock drift: {drift:.1f} seconds")

        except Exception as e:
            self.logger.debug(f"Error getting controller time: {e}")

        return result

    def _analyze_tag_database(self, conn: Any) -> Dict[str, Any]:
        """
        Analyze the tag database from pycomm3 LogixDriver.

        Returns detailed analysis including:
        - Tag counts by type (atomic vs structure)
        - Tag scope (controller vs program)
        - Programs discovered
        - External access settings
        - Firmware version indicators (v21+ instance addressing)
        """
        result: Dict[str, Any] = {
            "total_tags": 0,
            "atomic_tags": 0,
            "struct_tags": 0,
            "array_tags": 0,
            "controller_scoped": 0,
            "program_scoped": 0,
            "programs": [],
            "has_instance_ids": False,  # v21+ firmware indicator
            "external_access": {"read_write": 0, "read_only": 0, "none": 0},
            "largest_arrays": [],
        }

        if self._driver_type != "logix" or not hasattr(conn, "tags"):
            return result

        try:
            tags = conn.tags
            if not tags:
                # Try to upload tags if not already done
                if hasattr(conn, "get_tag_list"):
                    conn.get_tag_list()
                    tags = conn.tags

            if not tags:
                return result

            result["total_tags"] = len(tags)
            programs = set()
            arrays_with_size = []

            for tag_name, tag_info in tags.items():
                # Check tag type - pycomm3 uses dicts with specific keys
                if isinstance(tag_info, dict):
                    # pycomm3 uses 'tag_type' = 'atomic' or 'struct'
                    tag_type = tag_info.get("tag_type", "")

                    # Atomic vs structure
                    if tag_type == "atomic":
                        result["atomic_tags"] += 1
                    else:
                        result["struct_tags"] += 1

                    # Array detection - 'dim' is 0 for scalar, N for 1D array
                    # 'dimensions' is [N, 0, 0] for 1D, [N, M, 0] for 2D, etc.
                    dim = tag_info.get("dim", 0)
                    dimensions = tag_info.get("dimensions", [0, 0, 0])
                    if dim > 0 or (dimensions and dimensions[0] > 0):
                        result["array_tags"] += 1
                        # Calculate array size from dimensions
                        if dimensions:
                            size = 1
                            for d in dimensions:
                                if d > 0:
                                    size *= d
                            if size > 1:
                                arrays_with_size.append((tag_name, size, dimensions))

                    # Scope detection (program vs controller)
                    # Program-scoped tags have "Program:name.tagname" or "name:tagname" format
                    if ":" in tag_name:
                        result["program_scoped"] += 1
                        # Extract program name (before first colon or after "Program:")
                        if tag_name.startswith("Program:"):
                            prog_name = tag_name[8:].split(".")[0]
                        else:
                            prog_name = tag_name.split(":")[0]
                        if prog_name and not prog_name.startswith("Local"):
                            programs.add(prog_name)
                    else:
                        result["controller_scoped"] += 1

                    # Check for instance_id (v21+ firmware)
                    if tag_info.get("instance_id") is not None:
                        result["has_instance_ids"] = True

                    # External access settings (pycomm3 format: "Read/Write", "Read Only", "None")
                    ext_access = str(tag_info.get("external_access", "")).lower()
                    if "read/write" in ext_access:
                        result["external_access"]["read_write"] += 1
                    elif "read" in ext_access and "only" in ext_access:
                        result["external_access"]["read_only"] += 1
                    elif ext_access == "none":
                        result["external_access"]["none"] += 1

            result["programs"] = sorted(list(programs))

            # Top 5 largest arrays
            arrays_with_size.sort(key=lambda x: x[1], reverse=True)
            result["largest_arrays"] = [
                {"name": a[0], "size": a[1], "dimensions": a[2]} for a in arrays_with_size[:5]
            ]

            # Log summary
            self.logger.display(
                f"  Tags: {result['total_tags']} total "
                f"({result['atomic_tags']} atomic, {result['struct_tags']} struct, "
                f"{result['array_tags']} arrays)"
            )
            if result["programs"]:
                self.logger.display(f"  Programs: {', '.join(result['programs'][:5])}")
            if result["has_instance_ids"]:
                self.logger.debug("Firmware: v21+ (instance addressing enabled)")

        except Exception as e:
            self.logger.debug(f"Error analyzing tag database: {e}")

        return result

    def _dump_tags(
        self,
        conn: Any,
        output_dir: str,
        output_format: str,
    ) -> Dict[str, Any]:
        """
        Dump all tags with values using the central table formatting function.

        Exports:
        - Tag definitions (names, types, dimensions)
        - Live values for atomic tags

        Args:
            conn: pycomm3 LogixDriver connection
            output_dir: Output directory for files (default: current directory)
            output_format: Output format ("console", "csv", "json", "all")

        Returns:
            Dict with export summary
        """
        from oida.utils.export_utils import export_data

        result = {
            "exported": False,
            "tag_count": 0,
            "values_read": 0,
            "error": None,
        }

        if self._driver_type != "logix" or not hasattr(conn, "tags"):
            result["error"] = "Tag dump requires pycomm3 LogixDriver connection"
            return result

        try:
            # Ensure tags are loaded
            if not hasattr(conn, "tags") or not conn.tags:
                if hasattr(conn, "get_tag_list"):
                    self.logger.display("  Uploading tag database for dump...")
                    conn.get_tag_list()

            if not conn.tags:
                result["error"] = "No tags available"
                return result

            plc_name = conn.info.get("name", "unknown_plc").replace(" ", "_")
            output_dir = output_dir or "."

            # Build tag definitions table
            tag_rows = []
            for name, info in conn.tags.items():
                if isinstance(info, dict):
                    data_type = info.get("data_type_name", str(info.get("data_type", "?")))
                    # Truncate long type names for display
                    if len(data_type) > 25:
                        data_type = data_type[:22] + "..."
                    tag_rows.append(
                        [
                            name,
                            data_type,
                            info.get("tag_type", "?"),
                            str(info.get("dim", 0)),
                            info.get("external_access", "") or "",
                        ]
                    )

            result["tag_count"] = len(tag_rows)

            # Export tag definitions table
            if tag_rows:
                tag_headers = ["Tag Name", "Data Type", "Type", "Dim", "Access"]
                export_data(
                    tag_rows,
                    tag_headers,
                    output_format,
                    output_dir,
                    f"{plc_name}_tags",
                    f"Tags ({len(tag_rows)} total)",
                    logger=self.logger,
                )

            # Read atomic tag values (batch read for efficiency)
            atomic_tags = [
                name
                for name, info in conn.tags.items()
                if isinstance(info, dict)
                and info.get("tag_type") == "atomic"
                and not info.get("dim")
            ]

            value_rows = []
            if atomic_tags:
                self.logger.display(f"  Reading {len(atomic_tags)} atomic tag values...")
                batch_size = 100
                for i in range(0, len(atomic_tags), batch_size):
                    batch = atomic_tags[i : i + batch_size]
                    try:
                        results = conn.read(*batch)
                        for r in results:
                            if not r.error:
                                value = r.value
                                if hasattr(value, "__dict__"):
                                    value = str(value)
                                value_rows.append([r.tag, str(value)])
                    except Exception as e:
                        self.logger.debug(f"Batch read error: {e}")

            result["values_read"] = len(value_rows)

            # Export values table
            if value_rows:
                value_headers = ["Tag", "Value"]
                export_data(
                    value_rows,
                    value_headers,
                    output_format,
                    output_dir,
                    f"{plc_name}_values",
                    f"Tag Values ({len(value_rows)} read)",
                    logger=self.logger,
                )

            result["exported"] = True
            self.logger.success(
                f"Tags exported: {result['tag_count']} definitions, {result['values_read']} values"
            )

        except Exception as e:
            result["error"] = str(e)
            self.logger.error(f"Tag dump failed: {e}")

        return result

    def _enumerate_data_types(self, conn: Any) -> Dict[str, Any]:
        """
        Enumerate UDT (User-Defined Types) and AOI (Add-On Instructions) from Template Object.

        Returns:
        - UDT/AOI count and details
        - Member information for each type
        - Nested structure detection
        """
        result = {
            "total_types": 0,
            "udt_count": 0,
            "aoi_count": 0,
            "predefined_count": 0,
            "types": [],
        }

        if self._driver_type != "logix" or not hasattr(conn, "data_types"):
            return result

        try:
            data_types = conn.data_types
            if not data_types:
                # Try to get data types if not loaded
                if hasattr(conn, "get_tag_list"):
                    conn.get_tag_list()
                    data_types = conn.data_types

            if not data_types:
                return result

            result["total_types"] = len(data_types)

            # Predefined Rockwell types to exclude from UDT count
            predefined_patterns = {
                "BOOL",
                "SINT",
                "INT",
                "DINT",
                "LINT",
                "REAL",
                "LREAL",
                "STRING",
                "TIMER",
                "COUNTER",
                "CONTROL",
                "PID",
                "MESSAGE",
                "AXIS",
                "MOTION_GROUP",
                "COORDINATE_SYSTEM",
                "CAM",
                "CAM_PROFILE",
            }

            for type_name, type_info in data_types.items():
                if type_name.upper() in predefined_patterns:
                    result["predefined_count"] += 1
                    continue

                type_entry = {
                    "name": type_name,
                    "member_count": 0,
                    "size_bytes": None,
                    "is_aoi": False,
                    "members": [],
                }

                if isinstance(type_info, dict):
                    # Get member information
                    members = type_info.get("members", []) or type_info.get("attributes", [])
                    type_entry["member_count"] = len(members) if members else 0

                    # Get structure size
                    type_entry["size_bytes"] = type_info.get("template_size") or type_info.get(
                        "size"
                    )

                    # Detect AOI (Add-On Instruction) vs UDT
                    # AOIs typically have specific patterns in their names or attributes
                    if type_info.get("is_aoi") or "EnableIn" in str(members):
                        type_entry["is_aoi"] = True
                        result["aoi_count"] += 1
                    else:
                        result["udt_count"] += 1

                    # Store first 10 member names for inspection
                    if members:
                        for member in members[:10]:
                            if isinstance(member, dict):
                                member_name = member.get("name", member.get("Name", ""))
                                member_type = member.get("data_type", member.get("type", ""))
                                type_entry["members"].append(
                                    {"name": member_name, "type": member_type}
                                )
                            elif isinstance(member, str):
                                type_entry["members"].append({"name": member, "type": "unknown"})

                result["types"].append(type_entry)

            # Log summary
            self.logger.display(
                f"  Data Types: {result['udt_count']} UDTs, "
                f"{result['aoi_count']} AOIs, {result['predefined_count']} predefined"
            )

        except Exception as e:
            self.logger.debug(f"Error enumerating data types: {e}")

        return result

    def _get_all_tags_pycomm3(self, conn: Any) -> List[Dict[str, Any]]:
        """
        Get complete tag list from PLC using pycomm3 LogixDriver.

        Only works with LogixDriver (Rockwell PLCs).
        Returns list of tag info dicts with name, type, etc.
        """
        if self._driver_type != "logix":
            return []

        try:
            # Upload tag list (this can take a few seconds)
            self.logger.display("Uploading tag list from PLC...")
            tags = conn.get_tag_list()
            tag_list = []
            for t in tags:
                # pycomm3 get_tag_list() returns List[dict], not objects — the
                # old attribute access (t.tag_name) raised AttributeError on the
                # first entry, swallowed below, so this always returned [].
                tag_info = {
                    "name": t.get("tag_name"),
                    "type": t.get("data_type_name"),
                    "dim": t.get("dimensions"),
                    "instance_id": t.get("instance_id"),
                }
                tag_list.append(tag_info)
            self.logger.display(f"Found {len(tag_list)} tags")
            return tag_list
        except Exception as e:
            self.logger.debug(f"Failed to get tag list: {e}")
            return []

    def _identify_dangerous_tags(self, tags: List[str]) -> List[Dict[str, Any]]:
        """
        Identify potentially dangerous tags that could affect safety/operations.

        Args:
            tags: List of tag names to analyze

        Returns:
            List of dangerous tags with classification
        """
        dangerous = []

        for tag in tags:
            tag_upper = tag.upper()
            for pattern in DANGEROUS_TAG_PATTERNS:
                if re.match(pattern, tag_upper, re.IGNORECASE):
                    dangerous.append(
                        {
                            "tag": tag,
                            "pattern": pattern,
                            "risk": (
                                "high"
                                if "SAFETY" in tag_upper
                                or "ESTOP" in tag_upper
                                or "EMERGENCY" in tag_upper
                                else "medium"
                            ),
                        }
                    )
                    break

        if dangerous:
            self.logger.warning(f"Found {len(dangerous)} potentially dangerous tags:")
            for d in dangerous[:5]:  # Show first 5
                self.logger.warning(f"  {d['tag']} ({d['risk']} risk)")
            if len(dangerous) > 5:
                self.logger.warning(f"  ... and {len(dangerous) - 5} more")

        return dangerous
