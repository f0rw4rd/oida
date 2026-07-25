"""
EtherNet/IP Class Explorer Mixin

Handles CIP class discovery and attribute exploration:
- Discover available CIP classes
- Explore class and instance attributes in detail
- Format and print attribute tables
- Parse attribute values and descriptions
"""

from __future__ import annotations

from typing import Any, Dict, List, TYPE_CHECKING

from ....utils.vendor_maps import ethernetip_wellknown_class_types as wellknown_class_types

if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


class ClassExplorerMixin(_ScannerBase):
    """Mixin providing CIP class discovery and attribute exploration."""

    def _discover_classes(self, conn: Any) -> List[Dict[str, Any]]:
        """Discover available CIP classes (or skip for Logix-style tag-based devices)"""
        classes = []

        # For Logix-style devices, CIP class scanning doesn't work well
        # Modern PLCs use symbolic tags rather than traditional CIP objects
        if self.max_class == 0 and not self.full_enum:
            self.logger.debug("Class scanning disabled - using tag-based discovery")
            return classes

        # Determine scan range
        if self.full_enum:
            # Full enum: scan all classes 0x01-0xFF
            scan_range = 0xFF
            self.logger.display(f"Full enumeration: scanning classes 0x01-0x{scan_range:02X}...")
        else:
            # Normal mode: only try first few classes
            scan_range = min(self.max_class, 10) if self.max_class > 0 else 10
            self.logger.debug(f"Attempting CIP class scan (1-{scan_range})...")

        for class_id in range(1, scan_range + 1):
            try:
                # Use pycomm3 generic_message for class probing
                data = self._read_cip_attribute(conn, class_id, 1, 1)
                if data is not None:
                    class_info = {
                        "class_id": class_id,
                        "class_name": wellknown_class_types.get(class_id, f"Unknown_{class_id}"),
                        "accessible": True,
                        "sample_attribute": data.hex() if data else None,
                    }
                    classes.append(class_info)
                    self.logger.debug(f"Found class 0x{class_id:02X}: {class_info['class_name']}")
            except Exception as e:
                self.logger.debug(f"Class {class_id} not accessible: {e}")

        if classes:
            self.logger.display(f"Found {len(classes)} accessible CIP classes")
        else:
            self.logger.display(
                "No CIP classes found - this device likely uses tag-based access only"
            )

        return classes

    def _explore_classes(self, conn: Any, classes: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Explore specific classes in detail - shows class summary then combined attribute table"""
        attributes = {}
        all_rows = []  # Combined rows for all classes: (class_id, inst, attr, data, name, dtype, perm)
        class_summary = []  # (class_id, name, instances, attrs)

        # Check if Parameter Object (0x0F) is available for permission detection
        param_obj_info = self._check_parameter_object(conn)
        use_param_obj = param_obj_info["available"]

        # The write-test permission method issues LIVE Set_Attribute_Single
        # writes to the device, so it is only usable when BOTH --write and
        # --confirm are set. Without --confirm we must not write-test, so the
        # write-back fallback is unavailable and we degrade to "R?"/unknown.
        write_test_ok = self.test_write and getattr(self, "confirm", False)
        # NOTE: Parameter Object (0x0F) descriptor-based permission detection
        # (get_permission_from_descriptor) is not wired into _determine_permission:
        # there is no link-path mapping from an arbitrary (class, instance,
        # attribute) being explored back to the Parameter Object instance that
        # describes it. So the Parameter Object's mere presence must not be
        # treated as a usable detection method - only the write-test can
        # actually set can_detect_perms.
        can_detect_perms = write_test_ok

        # Inform user about permission detection method
        if use_param_obj:
            self.logger.display(
                f"Parameter Object (0x0F) available: {param_obj_info['num_instances']} parameters"
            )
            if write_test_ok:
                self.logger.display(
                    "  Using write-test method (Set_Attribute_Single + error code interpretation)"
                )
                self.logger.display(
                    "  Legend: R=read-only, RW=read/write, R?=needs auth, R*=state-dependent"
                )
            elif self.test_write:
                self.logger.warning(
                    "  --write write-back permission test requires --confirm (live writes)"
                )
                self.logger.display("  Perm column will show '???' (unknown)")
            else:
                self.logger.warning(
                    "  Cannot detect permissions - use --write to test with write-back method"
                )
                self.logger.display("  Perm column will show '???' (unknown)")
        elif write_test_ok:
            self.logger.display("Parameter Object (0x0F) not available")
            self.logger.display(
                "  Using write-test method (Set_Attribute_Single + error code interpretation)"
            )
            self.logger.display(
                "  Legend: R=read-only, RW=read/write, R?=needs auth, R*=state-dependent"
            )
        elif self.test_write:
            # --write requested but --confirm missing: never write-test live.
            self.logger.warning("Parameter Object (0x0F) not available")
            self.logger.warning(
                "  --write write-back permission test requires --confirm (live writes)"
            )
            self.logger.display("  Perm column will show '???' (unknown)")
        else:
            # No 0x0F and no --write flag
            self.logger.warning("Parameter Object (0x0F) not available")
            self.logger.warning("  Cannot detect attribute permissions without Parameter Object")
            self.logger.warning("  Use --write flag to test permissions via write-back method")
            self.logger.display("  Perm column will show '???' (unknown)")

        # Parse explore_class parameter
        if self.explore_class:
            try:
                explore_list = []
                for part in self.explore_class.split(","):
                    part = part.strip()
                    if part.startswith("0x"):
                        explore_list.append(int(part, 16))
                    else:
                        explore_list.append(int(part))
            except ValueError as e:
                self.logger.debug(f"explore classes failed: {e}")
                self.logger.fail(f"Invalid explore_class format: {self.explore_class}")
                return attributes
        else:
            # Use discovered classes
            explore_list = [cls["class_id"] for cls in classes]

        # Collect all data first
        for class_id in explore_list:
            class_attributes, rows, instances_found = self._explore_class_attributes(
                conn, class_id, can_detect_perms
            )
            if class_attributes:
                attributes[class_id] = class_attributes
                all_rows.extend(rows)
                class_name = wellknown_class_types.get(class_id, "Unknown")
                class_summary.append((class_id, class_name, instances_found, len(rows)))

        # Print object classes table first
        if class_summary:
            self._print_class_table(class_summary)

        # Print combined attribute table
        if all_rows:
            self._print_attr_table(all_rows)
            total_instances = sum(c[2] for c in class_summary)
            self.logger.display(
                f"Total: {len(class_summary)} classes, {total_instances} instances, {len(all_rows)} attributes"
            )

        return attributes

    def _print_class_table(self, class_summary: list) -> None:
        """Print a table of discovered CIP object classes"""
        # Calculate column widths
        max_name = max(len(name) for _, name, _, _ in class_summary) if class_summary else 10
        max_name = max(max_name, 10)  # Minimum for "Class Name"

        hdr_class = "\u2500" * 8
        hdr_name = "\u2500" * (max_name + 2)
        hdr_inst = "\u2500" * 11
        hdr_attr = "\u2500" * 12

        self.logger.display("")
        self.logger.display("CIP Object Classes:")
        self.logger.display(
            f"  \u250c{hdr_class}\u252c{hdr_name}\u252c{hdr_inst}\u252c{hdr_attr}\u2510"
        )
        self.logger.display(
            f"  \u2502 Class  \u2502 {'Class Name':<{max_name}} \u2502 Instances \u2502 Attributes \u2502"
        )
        self.logger.display(
            f"  \u251c{hdr_class}\u253c{hdr_name}\u253c{hdr_inst}\u253c{hdr_attr}\u2524"
        )

        for class_id, name, instances, attrs in class_summary:
            self.logger.display(
                f"  \u2502 0x{class_id:02X}   \u2502 {name:<{max_name}} \u2502 {instances:9d} \u2502 {attrs:10d} \u2502"
            )

        self.logger.display(
            f"  \u2514{hdr_class}\u2534{hdr_name}\u2534{hdr_inst}\u2534{hdr_attr}\u2518"
        )
        self.logger.display("")

    def _explore_class_attributes(
        self,
        conn: Any,
        class_id: int,
        can_detect_perms: bool,
    ) -> tuple:
        """Explore attributes of a specific class including all instances.

        Args:
            conn: pycomm3 connection
            class_id: CIP class ID to explore
            can_detect_perms: Whether permissions can be determined (0x0F available or --write set)

        Returns: (result_dict, rows_list, instances_found)
            rows_list contains tuples: (class_id, inst, attr, data, desc, dtype, perm)
        """
        from ..cip_definitions import parse_attribute, get_object_name

        class_name = get_object_name(class_id)
        result = {
            "class_id": class_id,
            "class_name": class_name,
            "class_attributes": {},
            "instances": {},
        }
        rows = []  # Collect rows: (class_id, inst, attr, data, desc, dtype, perm)

        # First, read class-level attributes (instance 0)
        class_attrs = {}
        for attr_id in range(1, min(self.max_attributes, 20) + 1):
            try:
                data = self._read_cip_attribute(conn, class_id, 0, attr_id)
                if data is not None:
                    name, dtype, parsed = parse_attribute(class_id, 0, attr_id, data)

                    # Determine permission
                    if can_detect_perms:
                        perm = self._determine_permission(conn, class_id, 0, attr_id, data)
                    else:
                        perm = "???"

                    class_attrs[attr_id] = {
                        "name": name,
                        "type": dtype,
                        "value": self._serialize_value(parsed),
                        "raw": data.hex() if data else None,
                        "perm": perm,
                    }
                    rows.append((class_id, 0, attr_id, data, name, dtype, perm))
            except Exception as e:
                self.logger.debug(f"explore class attributes failed: {e}")

        result["class_attributes"] = class_attrs

        # Determine number of instances from class attribute 2 (if available)
        max_instances = 1
        if 2 in class_attrs and class_attrs[2].get("value"):
            try:
                max_instances = int(class_attrs[2]["value"])
            except (ValueError, TypeError) as e:
                self.logger.debug(f"explore class attributes failed: {e}")

        # For known multi-instance classes, scan more
        if class_id in [0x04, 0x47, 0x48, 0x64, 0x65, 0xF4]:
            max_instances = max(max_instances, 40)

        # Enumerate instances
        instances_found = 0
        for instance in range(1, min(max_instances + 1, 100)):
            # Check if instance exists
            test = self._read_cip_attribute(conn, class_id, instance, 1)
            if test is None:
                continue

            instances_found += 1
            instance_attrs = {}

            for attr_id in range(1, self.max_attributes + 1):
                try:
                    data = self._read_cip_attribute(conn, class_id, instance, attr_id)
                    if data is not None:
                        name, dtype, parsed = parse_attribute(class_id, instance, attr_id, data)

                        # Determine permission
                        if can_detect_perms:
                            perm = self._determine_permission(
                                conn, class_id, instance, attr_id, data
                            )
                        else:
                            perm = "???"

                        instance_attrs[attr_id] = {
                            "name": name,
                            "type": dtype,
                            "value": self._serialize_value(parsed),
                            "raw": data.hex() if data else None,
                            "perm": perm,
                        }
                        rows.append((class_id, instance, attr_id, data, name, dtype, perm))
                except Exception as e:
                    self.logger.debug(f"explore class attributes failed: {e}")

            result["instances"][instance] = instance_attrs

        return result, rows, instances_found

    def _serialize_value(self, value: Any) -> Any:
        """Serialize parsed value for JSON export"""
        if value is None:
            return None
        if isinstance(value, bytes):
            return value.hex()
        if isinstance(value, dict):
            return {k: self._serialize_value(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [self._serialize_value(v) for v in value]
        return value

    def _print_attr_table(self, rows: list) -> None:
        """Print attributes as a formatted table with dynamic column widths.

        Args:
            rows: List of 7-tuples (class_id, inst, attr, data, desc, dtype, perm)
        """
        from ..cip_definitions import parse_attribute

        # Pre-process rows to get parsed values and calculate column widths
        processed = []
        max_val, max_desc, max_type = 5, 11, 4  # Minimum widths for headers

        for class_id, instance, attr_id, data, desc, dtype, perm in rows:
            _, _, parsed_val = parse_attribute(class_id, instance, attr_id, data)
            val = self._format_parsed_value(parsed_val, data)
            processed.append((class_id, instance, attr_id, val, desc, dtype, perm))
            max_val = max(max_val, len(val))
            max_desc = max(max_desc, len(desc))
            max_type = max(max_type, len(dtype))

        # Build dynamic column separators
        hdr_class = "\u2500" * 8
        hdr_inst = "\u2500" * 6
        hdr_attr = "\u2500" * 6
        hdr_val = "\u2500" * (max_val + 2)
        hdr_desc = "\u2500" * (max_desc + 2)
        hdr_type = "\u2500" * (max_type + 2)
        hdr_perm = "\u2500" * 6

        # Header
        self.logger.display("CIP Attributes:")
        self.logger.display(
            f"  \u250c{hdr_class}\u252c{hdr_inst}\u252c{hdr_attr}\u252c{hdr_perm}\u252c{hdr_val}\u252c{hdr_desc}\u252c{hdr_type}\u2510"
        )
        self.logger.display(
            f"  \u2502 Class  \u2502 Inst \u2502 Attr \u2502 Perm \u2502 {'Value':<{max_val}} \u2502 {'Description':<{max_desc}} \u2502 {'Type':<{max_type}} \u2502"
        )
        self.logger.display(
            f"  \u251c{hdr_class}\u253c{hdr_inst}\u253c{hdr_attr}\u253c{hdr_perm}\u253c{hdr_val}\u253c{hdr_desc}\u253c{hdr_type}\u2524"
        )

        for class_id, instance, attr_id, val, desc, dtype, perm in processed:
            self.logger.display(
                f"  \u2502 0x{class_id:02X}   \u2502 {instance:4d} \u2502 {attr_id:4d} \u2502 {perm:4s} \u2502 {val:<{max_val}} \u2502 {desc:<{max_desc}} \u2502 {dtype:<{max_type}} \u2502"
            )

        self.logger.display(
            f"  \u2514{hdr_class}\u2534{hdr_inst}\u2534{hdr_attr}\u2534{hdr_perm}\u2534{hdr_val}\u2534{hdr_desc}\u2534{hdr_type}\u2518"
        )

    def _format_parsed_value(self, parsed_val: Any, data: bytes) -> str:
        """Format a parsed attribute value for display"""
        if parsed_val is None:
            return self._format_raw_bytes(data)

        # Handle different parsed value types
        if isinstance(parsed_val, dict):
            # Struct - show key fields
            if "mac" in parsed_val and "ip" in parsed_val:
                # DLR node address - show MAC/IP
                return f"{parsed_val['mac']} ({parsed_val['ip']})"
            if "ip" in parsed_val:
                return parsed_val.get("ip", "")
            if "address" in parsed_val:
                return parsed_val.get("address", "")
            # Just show first few key=value pairs
            items = list(parsed_val.items())[:2]
            return ", ".join(f"{k}={v}" for k, v in items)
        elif isinstance(parsed_val, str):
            return parsed_val
        elif isinstance(parsed_val, bool):
            return "True" if parsed_val else "False"
        elif isinstance(parsed_val, (int, float)):
            return str(parsed_val)
        elif isinstance(parsed_val, bytes):
            return self._format_raw_bytes(parsed_val)
        else:
            return str(parsed_val)

    def _format_raw_bytes(self, data: bytes) -> str:
        """Format raw bytes for display"""
        if not data:
            return "None"
        hex_val = data.hex()
        # Truncate long values
        if len(hex_val) > 40:
            hex_val = hex_val[:37] + "..."
        # Try to decode as ASCII if printable
        if data and len(data) <= 32:
            try:
                text = data.decode("ascii", errors="ignore")
                printable = "".join(c for c in text if c.isprintable())
                if len(printable) >= 3:
                    return f"'{printable}'"
            except Exception as e:
                self.logger.debug(f"format raw bytes failed: {e}")
        return hex_val
