"""
TASE.2 Control Mixin

Handles Block 5 device control operations:
- Control point access testing
- Write access testing
- Device tag get/set
- Select-Before-Operate (SBO) with CheckBackID
- Device operate with CheckBackID verification
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List

if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


class ControlMixin(_ScannerBase):
    """Mixin providing TASE.2 device control (Block 5) operations."""

    def _test_control_access(self, connection: Any) -> List[Dict[str, Any]]:
        """Test control point access (Block 5)."""
        control_points = []

        # Look for potential control points in domains
        for domain in self.domains:
            variables = connection.get_domain_variables(domain.name)

            for var in variables:
                var_name = str(var)
                name_lower = var_name.lower()
                if any(
                    kw in name_lower
                    for kw in [
                        "control",
                        "command",
                        "setpoint",
                        "breaker",
                        "switch",
                        "valve",
                        "output",
                        "operate",
                    ]
                ):
                    control_info = {
                        "domain": domain.name,
                        "name": var_name,
                        "selectable": False,
                        "operable": False,
                    }

                    # Don't actually try to control in read-only mode
                    if not self.read_only:
                        try:
                            # Try select (SBO)
                            connection.select_device(domain.name, var_name)
                            control_info["selectable"] = True
                            self.logger.warning(f"SELECTABLE: {domain.name}/{var_name}")
                        except Exception as e:
                            self.logger.debug(f"connection.select_device(domain.name,...: {e}")

                    control_points.append(control_info)

        if control_points:
            self.logger.display(f"Found {len(control_points)} potential control point(s)")

        return control_points

    def _test_write_access(self, connection: Any, results: Dict[str, Any]) -> None:
        """Test write access to data points."""
        writable_count = 0

        for point in results.get("data_points", []):
            if not point.get("readable"):
                continue

            try:
                # Read current value
                current = connection.read_point(point["domain"], point["name"])

                # Try to write same value back
                connection.write_point(point["domain"], point["name"], current.value)

                point["writable"] = True
                writable_count += 1
                self.logger.security_finding(
                    "Writable access", f"TASE.2 writable point: {point['domain']}/{point['name']}"
                )

            except Exception:
                point["writable"] = False

        if writable_count > 0:
            self.logger.display(f"Found {writable_count} writable point(s)")

    # =========================================================================
    # Block 5 Device Operations
    # =========================================================================

    def get_tag(self, connection: Any, domain: str, device: str) -> Dict[str, Any]:
        """
        Get tag value for a device.

        Tag values: NO_TAG, OPEN_AND_CLOSE_INHIBIT, CLOSE_ONLY

        Uses connection.get_tag() (pyiec61850-ng >= 1.6.0.9) which returns
        a TagState dataclass, falling back to manual variable reads.

        Args:
            connection: Active TASE.2 connection
            domain: Domain name
            device: Device name

        Returns:
            Dictionary with tag_value and reason
        """
        tag_info = {
            "domain": domain,
            "device": device,
            "tag_value": "UNKNOWN",
            "reason": "",
        }

        try:
            tag_state = connection.get_tag(domain, device)
            tag_info["tag_value"] = tag_state.tag_name
            tag_info["reason"] = tag_state.reason
            self.logger.display(f"Tag for {domain}/{device}: {tag_info['tag_value']}")
        except Exception as e:
            self.logger.debug(f"Error getting tag for {domain}/{device}: {e}")

        return tag_info

    def set_tag(
        self,
        connection: Any,
        domain: str,
        device: str,
        tag_value: str,
        reason: str = "",
    ) -> bool:
        """
        Set tag value for a device.

        Args:
            connection: Active TASE.2 connection
            domain: Domain name
            device: Device name
            tag_value: One of NO_TAG, OPEN_AND_CLOSE_INHIBIT, CLOSE_ONLY
            reason: Optional reason string

        Returns:
            True if successful
        """
        if self.read_only:
            self.logger.warning("Cannot set tag in read-only mode")
            return False

        try:
            tag_var = f"{device}_Tag"
            tag_data = {"TagValue": tag_value, "Reason": reason}

            result = connection.write_point(domain, tag_var, tag_data)

            if result:
                self.logger.display(f"Set tag for {domain}/{device} to {tag_value}")
            return bool(result)

        except Exception as e:
            self.logger.fail(f"Failed to set tag: {e}")
            return False

    def select_device_with_checkback(
        self, connection: Any, domain: str, device: str
    ) -> Dict[str, Any]:
        """
        Select SBO device and return CheckBackID.

        The CheckBackID is used to verify the device before operate.

        Args:
            connection: Active TASE.2 connection
            domain: Domain name
            device: Device name

        Returns:
            Dictionary with success, check_back_id, and state
        """
        result = {
            "domain": domain,
            "device": device,
            "success": False,
            "check_back_id": None,
            "state": "IDLE",
            "error": None,
        }

        try:
            # Read <device>_SBO variable for CheckBackID
            sbo_var = f"{device}_SBO"
            sbo = connection.read_point(domain, sbo_var)

            if sbo:
                result["success"] = True
                result["check_back_id"] = sbo.value
                result["state"] = "ARMED"
                self.device_states[f"{domain}/{device}"] = "ARMED"

                self.logger.display(f"Selected {domain}/{device}, CheckBackID: {sbo.value}")

        except Exception as e:
            result["error"] = str(e)
            self.logger.debug(f"Select failed for {domain}/{device}: {e}")

        return result

    def operate_device_with_checkback(
        self,
        connection: Any,
        domain: str,
        device: str,
        value: Any,
        check_back_id: Any = None,
    ) -> Dict[str, Any]:
        """
        Operate device with optional CheckBackID verification.

        Args:
            connection: Active TASE.2 connection
            domain: Domain name
            device: Device name
            value: Command value
            check_back_id: Optional CheckBackID from select

        Returns:
            Dictionary with success and any error
        """
        result = {
            "domain": domain,
            "device": device,
            "success": False,
            "error": None,
        }

        if self.read_only:
            result["error"] = "Read-only mode"
            self.logger.warning("Cannot operate device in read-only mode")
            return result

        # Check device state for SBO devices
        device_key = f"{domain}/{device}"
        if check_back_id is not None:
            if self.device_states.get(device_key) != "ARMED":
                result["error"] = "Device not in ARMED state - select first"
                self.logger.warning(f"Device {device_key} not selected")
                return result

        try:
            # For SBO devices, include CheckBackID in the command
            if check_back_id is not None:
                cmd = {"Value": value, "CheckBackID": check_back_id}
            else:
                cmd = value

            success = connection.write_point(domain, device, cmd)
            result["success"] = bool(success)

            if success:
                self.device_states[device_key] = "IDLE"
                self.logger.display(f"Operated {domain}/{device} with value {value}")

        except Exception as e:
            result["error"] = str(e)
            self.logger.fail(f"Operate failed for {domain}/{device}: {e}")

        return result
