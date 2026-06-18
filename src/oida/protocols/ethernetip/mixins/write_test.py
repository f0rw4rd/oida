"""
EtherNet/IP Write Test Mixin

Handles attribute write testing and permission detection:
- Check Parameter Object (0x0F) availability
- Get permissions via Parameter Object descriptors
- Test write access with CIP status interpretation
- Determine attribute permissions (read-only, read-write, etc.)
- Test and summarize write access across all attributes
"""

from __future__ import annotations

import struct
from typing import Any, Dict, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


class WriteTestMixin(_ScannerBase):
    """Mixin providing CIP attribute write testing and permission detection."""

    def _check_parameter_object(self, conn: Any) -> dict:
        """Check if Parameter Object (Class 0x0F) is implemented.

        The Parameter Object provides runtime access to attribute metadata
        including read/write permissions via the Descriptor attribute (attr 4).

        Returns:
            Dict with:
                - available: True if Parameter Object exists
                - num_instances: Number of parameter instances
                - full_support: True if device supports full parameter attributes
        """
        result = {
            "available": False,
            "num_instances": 0,
            "full_support": False,
        }

        # Try to read Parameter Object class attribute 2 (Max Instance)
        data = self._read_cip_attribute(conn, 0x0F, 0, 2)
        if data is None:
            return result

        result["available"] = True
        if len(data) >= 2:
            result["num_instances"] = struct.unpack("<H", data[:2])[0]

        # Check class attribute 8 (Class Descriptor) for full vs stub support
        desc_data = self._read_cip_attribute(conn, 0x0F, 0, 8)
        if desc_data and len(desc_data) >= 2:
            class_desc = struct.unpack("<H", desc_data[:2])[0]
            # Bit 0 indicates full parameter support
            result["full_support"] = bool(class_desc & 0x0001)

        return result

    def _get_permission_via_parameter_object(self, conn: Any, param_instance: int) -> Optional[str]:
        """Get attribute permission from Parameter Object Descriptor.

        Args:
            conn: pycomm3 connection
            param_instance: Parameter instance number (maps to attribute/parameter)

        Returns:
            Permission string: "R", "W", "RW", or None if not available
        """
        from ..cip_definitions import get_permission_from_descriptor

        # Read Descriptor attribute (attribute 4) from Parameter Object
        data = self._read_cip_attribute(conn, 0x0F, param_instance, 4)
        if data is None or len(data) < 2:
            return None

        descriptor = struct.unpack("<H", data[:2])[0]
        return get_permission_from_descriptor(descriptor)

    def _test_write_with_status(
        self,
        conn: Any,
        class_id: int,
        instance: int,
        attr_id: int,
        value: bytes,
    ) -> tuple:
        """Test write access and return status code for interpretation.

        Args:
            conn: pycomm3 connection
            class_id: CIP class ID
            instance: Instance number (0=class, 1+=instance)
            attr_id: Attribute ID
            value: Value to write (same value to avoid changes)

        Returns:
            Tuple of (success: bool, status_code: int, extended_status: list)
        """
        if not hasattr(conn, "generic_message"):
            return (False, -1, [])

        try:
            result = conn.generic_message(
                service=0x10,  # Set_Attribute_Single
                class_code=class_id,
                instance=instance,
                attribute=attr_id,
                request_data=value,
                connected=True,
                unconnected_send=False,
            )

            if result is None:
                return (False, -1, [])

            # Extract status from result
            # pycomm3 stores CIP status in different places depending on version
            status = getattr(result, "service_status", None)
            if status is None:
                # Try to get status from error string
                error_str = str(getattr(result, "error", ""))
                if "attribute not settable" in error_str.lower():
                    status = 0x0E  # Attribute not settable
                elif "privilege violation" in error_str.lower():
                    status = 0x0F  # Privilege violation
                elif "not supported" in error_str.lower():
                    status = 0x08  # Service not supported
                elif result.error:
                    status = 0x0E  # Default to read-only if error with no status
                else:
                    status = 0x00  # Success

            extended = getattr(result, "extended_status", []) or []

            return (not result.error, status, extended)

        except Exception as e:
            self.logger.debug(f"Write test 0x{class_id:02X}/{instance}/{attr_id}: {e}")
            return (False, -1, [])

    def _determine_permission(
        self,
        conn: Any,
        class_id: int,
        instance: int,
        attr_id: int,
        value: bytes,
        use_param_obj: bool,
        param_instance_map: Optional[dict] = None,
    ) -> str:
        """Determine attribute permission using best available method.

        Strategy:
        1. If Parameter Object available, try to get permission from descriptor
        2. Otherwise, use write-test approach and interpret error codes

        Args:
            conn: pycomm3 connection
            class_id: CIP class ID
            instance: Instance number
            attr_id: Attribute ID
            value: Current attribute value (for write-back test)
            use_param_obj: True if Parameter Object is available
            param_instance_map: Optional mapping of (class,inst,attr) -> param instance

        Returns:
            Permission string: "R", "W", "RW", "R?", "R*", or "?"
        """
        from ..cip_definitions import interpret_write_error

        # Method 1: Try Parameter Object if available
        if use_param_obj and param_instance_map:
            key = (class_id, instance, attr_id)
            if key in param_instance_map:
                perm = self._get_permission_via_parameter_object(conn, param_instance_map[key])
                if perm:
                    return perm

        # Method 2: Write-test with error interpretation (only if --write flag set)
        if self.test_write and value:
            success, status, _ = self._test_write_with_status(
                conn, class_id, instance, attr_id, value
            )
            if success:
                return "RW"
            elif status >= 0:
                perm, _ = interpret_write_error(status)
                return perm

        # No permission info available
        return "?"

    def _test_attribute_write(
        self,
        conn: Any,
        class_id: int,
        instance: int,
        attr_id: int,
        original_value: bytes,
    ) -> bool:
        """Test if an attribute is writable using pycomm3.

        Args:
            conn: pycomm3 connection
            class_id: CIP class ID
            instance: Instance number (0=class attrs, 1+=instance attrs)
            attr_id: Attribute ID
            original_value: Original raw bytes to write back

        Returns:
            True if write succeeded, False otherwise
        """
        if not hasattr(conn, "generic_message"):
            return False

        try:
            # Try to write the same value back using Set_Attribute_Single (0x10)
            result = conn.generic_message(
                service=0x10,  # Set_Attribute_Single
                class_code=class_id,
                instance=instance,
                attribute=attr_id,
                request_data=original_value,
                connected=True,
                unconnected_send=False,
            )
            return result is not None and not result.error
        except Exception as e:
            self.logger.debug(f"test attribute write failed: {e}")
            return False

    def _test_write_access(self, conn: Any, attributes: Dict[str, Any]) -> Dict[str, Any]:
        """Summarize write access from already-collected permission data.

        Permission detection is now done inline during _explore_class_attributes.
        This function just summarizes the results.

        Args:
            conn: pycomm3 connection (not used - kept for API compatibility)
            attributes: Dict from _explore_classes with structure:
                {class_id: {"class_attributes": {...}, "instances": {...}}}

        Returns:
            Dict summarizing writable attributes by class
        """
        write_results = {}

        if self.read_only:
            return write_results

        # Permissions are already determined in _explore_class_attributes
        # Just summarize the results here

        total_tested = 0
        total_writable = 0
        writable_attrs = []

        for class_key, class_data in attributes.items():
            class_id = int(class_key)
            class_name = class_data.get("class_name", f"0x{class_id:02X}")
            class_write_results = {"class_attributes": {}, "instances": {}}

            # Check class-level attributes (instance 0)
            class_attrs = class_data.get("class_attributes", {})
            for attr_id, attr_info in class_attrs.items():
                perm = attr_info.get("perm", "?")
                if perm != "?":
                    total_tested += 1
                    writable = perm in ("RW", "W")
                    class_write_results["class_attributes"][attr_id] = {
                        "writable": writable,
                        "perm": perm,
                        "name": attr_info.get("name", ""),
                    }
                    if writable:
                        total_writable += 1
                        writable_attrs.append(
                            f"{class_name} class attr {attr_id} ({attr_info.get('name', '')})"
                        )

            # Check instance-level attributes
            instances = class_data.get("instances", {})
            for instance_key, instance_attrs in instances.items():
                instance = int(instance_key)
                instance_results = {}

                for attr_id, attr_info in instance_attrs.items():
                    perm = attr_info.get("perm", "?")
                    if perm != "?":
                        total_tested += 1
                        writable = perm in ("RW", "W")
                        instance_results[attr_id] = {
                            "writable": writable,
                            "perm": perm,
                            "name": attr_info.get("name", ""),
                        }
                        if writable:
                            total_writable += 1
                            writable_attrs.append(
                                f"{class_name} inst {instance} attr {attr_id} ({attr_info.get('name', '')})"
                            )

                if instance_results:
                    class_write_results["instances"][instance] = instance_results

            if class_write_results["class_attributes"] or class_write_results["instances"]:
                write_results[class_id] = class_write_results

        self.logger.display(
            f"Write test complete: {total_writable}/{total_tested} attributes writable"
        )
        return write_results
