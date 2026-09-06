"""
HART Device Info Mixin

Handles device identification and process variable reading:
- Device identification (Command 0) and tag info (Command 13)
- Primary variable reading (Command 1)
- Current and percent of range reading (Command 2)
- All dynamic variables reading (Command 3)
- Output information reading (Command 15)
- Additional device status reading (Command 48)
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List, Tuple

if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


class DeviceInfoMixin(_ScannerBase):
    """Mixin providing device identification and process variable reading."""

    def read_device_info(self, client=None):
        """Read device identification (Command 0) and tag info (Command 13).

        Uses the library's parse_cmd0() to decode Command 0 response into
        a DeviceInfo dataclass, then maps it to our HARTDeviceInfo.
        """
        from ..scanner import HARTDeviceInfo, PhysicalSignaling
        from ..hartip import get_vendor_name

        client = client or self.client
        if not client:
            return None

        try:
            response = client.read_unique_id(self.poll_address)
            if response.response_code != 0:
                return None

            # Use resp.parsed auto-dispatch (v0.3.0)
            lib_info = response.parsed

            info = HARTDeviceInfo()
            info.manufacturer_id = lib_info.manufacturer_id
            info.manufacturer_name = lib_info.manufacturer_name or get_vendor_name(
                lib_info.manufacturer_id
            )
            info.device_type = lib_info.device_type
            info.protocol_revision = lib_info.hart_revision
            info.device_revision = lib_info.device_revision
            info.software_revision = lib_info.software_revision
            info.hardware_revision = lib_info.hardware_revision
            info.physical_signaling_code = lib_info.physical_signaling
            info.unique_id = lib_info.unique_address

            # Derive write-protected / config-changed from flags
            info.write_protected = bool(lib_info.flags & 0x80)
            info.config_changed = bool(lib_info.flags & 0x40)

            # Detect WirelessHART from signaling code
            if lib_info.physical_signaling == PhysicalSignaling.WIRELESS_HART:
                info.is_wireless = True

            # Read tag/descriptor (Command 13) using resp.parsed
            try:
                tag_response = client.read_tag_descriptor_date(self.poll_address)
                if tag_response.response_code == 0 and len(tag_response.payload) >= 21:
                    tag_data = tag_response.parsed
                    if tag_data:
                        info.tag = tag_data.get("tag", "")
                        info.descriptor = tag_data.get("descriptor", "")
                        info.date = tag_data.get("date", "")
            except Exception as e:
                self.logger.debug(f"Failed to get tag_response: {e}")

            info.poll_address = self.poll_address
            return info

        except Exception as e:
            self.logger.debug(f"Error reading device info: {e}")
            return None

    def read_primary_variable(self, client=None):
        """Read primary variable (Command 1).

        Uses the library's parse_cmd1() for decoding.
        """
        from ..scanner import HARTVariable
        from ..hartip import get_unit_name

        client = client or self.client
        if not client:
            return None

        try:
            response = client.read_primary_variable(self.poll_address)
            if response.response_code != 0:
                return None

            var = response.parsed
            if var is None:
                return None

            return HARTVariable(
                name="Primary Variable",
                value=var.value,
                units_code=var.unit_code,
                units_name=var.unit_name or get_unit_name(var.unit_code),
                status=0,
            )

        except Exception as e:
            self.logger.debug(f"Error reading PV: {e}")
        return None

    def read_current_and_percent(self, client=None) -> Tuple[float, float]:
        """Read loop current and percent of range (Command 2).

        Uses the library's parse_cmd2() for decoding.
        """
        client = client or self.client
        if not client:
            return (0.0, 0.0)

        try:
            response = client.read_current_and_percent(self.poll_address)
            if response.response_code != 0:
                return (0.0, 0.0)

            result = response.parsed
            if result:
                return (result.get("current_mA", 0.0), result.get("percent_range", 0.0))

        except Exception as e:
            self.logger.debug(f"Failed to get response: {e}")
        return (0.0, 0.0)

    def read_all_variables(self, client=None) -> List:
        """Read all dynamic variables (Command 3).

        Uses the library's parse_cmd3() for decoding.
        Returns up to 4 dynamic variables plus loop current.
        """
        from ..scanner import HARTVariable
        from ..hartip import HARTCommand, get_unit_name

        client = client or self.client
        if not client:
            return []

        variables = []

        try:
            response = client.send_command(HARTCommand.READ_DYNAMIC_VARS, self.poll_address)
            if response.response_code != 0:
                return variables

            result = response.parsed
            if not result:
                return variables

            # Add loop current
            loop_current = result.get("loop_current")
            if loop_current is not None:
                variables.append(
                    HARTVariable(
                        name="Loop Current",
                        value=loop_current,
                        units_code=39,  # mA
                        units_name="mA",
                        status=0,
                    )
                )

            # Add dynamic variables (PV, SV, TV, QV)
            var_names = {
                "PV": "Primary Variable",
                "SV": "Secondary Variable",
                "TV": "Tertiary Variable",
                "QV": "Quaternary Variable",
            }
            for lib_var in result.get("variables", []):
                name = var_names.get(lib_var.label, lib_var.label)
                variables.append(
                    HARTVariable(
                        name=name,
                        value=lib_var.value,
                        units_code=lib_var.unit_code,
                        units_name=lib_var.unit_name or get_unit_name(lib_var.unit_code),
                        status=0,
                    )
                )

        except Exception as e:
            self.logger.debug(f"Error reading variables: {e}")

        return variables

    def read_output_info(self, client=None) -> Dict[str, Any]:
        """Read output information (Command 15).

        Uses the library's parse_cmd15() for decoding.
        """
        client = client or self.client
        if not client:
            return {}

        try:
            response = client.read_output_info(self.poll_address)
            if response.response_code != 0:
                return {}

            result = response.parsed
            if not result:
                return {}

            return {
                "alarm_selection": result.get("alarm_selection_code", 0),
                "transfer_function": result.get("transfer_function_code", 0),
                "units_code": result.get("range_units_code", 0),
                "units_name": result.get("range_unit_name", ""),
                "upper_range": result.get("upper_range_value", 0.0),
                "lower_range": result.get("lower_range_value", 0.0),
                "damping_seconds": result.get("damping_value", 0.0),
            }

        except Exception as e:
            self.logger.debug(f"Error reading output info: {e}")

        return {}

    def read_additional_status(self, client=None) -> Dict[str, Any]:
        """Read additional device status (Command 48).

        Uses resp.parsed for auto-dispatch and decode_extended_device_status()
        for human-readable flag interpretation.
        """
        from ..hartip import decode_extended_device_status

        client = client or self.client
        if not client:
            return {}

        try:
            response = client.read_additional_status(self.poll_address)
            if response.response_code != 0:
                return {}

            result = response.parsed or {}

            # Decode extended device status flags if present
            ext_status = result.get("extended_device_status", 0)
            if ext_status:
                result["extended_device_status_decoded"] = decode_extended_device_status(ext_status)

            return result

        except Exception as e:
            self.logger.debug(f"Error reading additional status: {e}")

        return {}
