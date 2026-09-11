"""
Snap7 Device Info Mixin

Handles device identification and status:
- CPU info extraction with timeout protection
- PLC run status detection
- Firmware version extraction (multi-method)
- S7 series identification from MLFB order codes
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict

if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


def decode_s7_field(value: Any) -> Any:
    """Decode a raw snap7 ctypes field into a clean string.

    python-snap7 structs (S7CpuInfo, TS7BlockInfo, ...) expose fixed-size
    char-array fields that read back as ``bytes`` at runtime. Decode those
    to ``ascii`` and strip trailing NULs/whitespace so downstream JSON
    export doesn't stringify them as ``"b'...'"``. Non-bytes values (already
    ``str``, ``None``, missing fields defaulted via ``getattr``) pass through
    unchanged.
    """
    if isinstance(value, bytes):
        return value.decode("ascii", errors="ignore").strip("\x00")
    return value


class DeviceInfoMixin(_ScannerBase):
    """Mixin providing CPU info, PLC status, firmware version, and series identification."""

    def _get_cpu_info(self, connection: Any) -> Dict[str, Any]:
        """Get CPU information with timeout protection"""
        from ..scanner import _run_with_timeout
        from ....utils.vendor_maps import lookup_s7_series

        self.logger.debug("Fetching CPU info...")
        timeout = self.timeout

        def fetch_cpu_info():
            cpu_info = connection.get_cpu_info()
            # Decode bytes to strings if needed
            module_type = cpu_info.ModuleTypeName
            if isinstance(module_type, bytes):
                module_type = module_type.decode("ascii", errors="ignore").strip("\x00")
            serial_number = cpu_info.SerialNumber
            if isinstance(serial_number, bytes):
                serial_number = serial_number.decode("ascii", errors="ignore").strip("\x00")
            as_name = cpu_info.ASName
            if isinstance(as_name, bytes):
                as_name = as_name.decode("ascii", errors="ignore").strip("\x00")
            module_name = cpu_info.ModuleName
            if isinstance(module_name, bytes):
                module_name = module_name.decode("ascii", errors="ignore").strip("\x00")
            copyright_info = cpu_info.Copyright
            if isinstance(copyright_info, bytes):
                copyright_info = copyright_info.decode("ascii", errors="ignore").strip("\x00")

            s7_series = lookup_s7_series(module_type)
            return {
                "module_type": module_type,
                "serial_number": serial_number,
                "as_name": as_name,
                "module_name": module_name,
                "copyright": copyright_info,
                "s7_series": s7_series,
            }

        result = _run_with_timeout(
            fetch_cpu_info,
            timeout_seconds=timeout,
            error_msg="CPU info not available (timeout - some PLCs don't support this)",
        )

        if isinstance(result, dict) and result.get("error"):
            self.logger.fail(f"Could not get CPU info: {result['error']}")
            return result

        # Success
        self.logger.debug(
            "CPU info: type=%s series=%s serial=%s",
            result["module_type"],
            result["s7_series"],
            result["serial_number"],
        )
        self.logger.display(
            f"S7 CPU: {result['module_type']} ({result['s7_series']}) - {result['module_name']}"
        )
        self.logger.debug(f"Serial Number: {result['serial_number']}")

        return result

    def _get_plc_status(self, connection: Any) -> Dict[str, Any]:
        """Get PLC status information with timeout protection"""
        from ..scanner import _run_with_timeout

        self.logger.debug("Fetching PLC run status...")
        timeout = self.timeout

        def fetch_status():
            # get_cpu_state() returns a string like "S7CpuStatusRun"
            cpu_state = connection.get_cpu_state()
            # Map string to readable status
            state_str = str(cpu_state) if cpu_state else "Unknown"
            if "Run" in state_str:
                status = "Run"
            elif "Stop" in state_str:
                status = "Stop"
            else:
                status = state_str
            return {
                "status": status,
                "status_raw": state_str,
            }

        result = _run_with_timeout(
            fetch_status,
            timeout_seconds=timeout,
            error_msg="CPU state not available (timeout - some PLCs don't support this)",
        )

        if isinstance(result, dict) and result.get("error"):
            self.logger.fail(f"Could not get PLC status: {result['error']}")
            return result

        # Success
        self.logger.display(f"PLC Status: {result['status']}")
        return result

    def get_firmware_version(self, connection: Any) -> Dict[str, Any]:
        """Extract comprehensive firmware information using multiple methods"""
        from ..models import S7FirmwareVersion
        from ..szl_parser import SZLParser
        from ....utils.vendor_maps import lookup_s7_series

        result = {
            "version": None,
            "version_str": None,
            "order_code": None,
            "series": None,
            "serial": None,
            "error": None,
        }
        errors = []

        # Method 1: Direct order code (fastest and most reliable)
        self.logger.debug("Firmware method 1: order code...")
        try:
            oc = connection.get_order_code()
            version = S7FirmwareVersion.from_order_code(oc.V1, oc.V2, oc.V3)
            result["version"] = version
            result["version_str"] = str(version)
            # Decode order code (python-snap7 S7OrderCode exposes OrderCode)
            code = getattr(oc, "OrderCode", None)
            if code is not None:
                if isinstance(code, bytes):
                    code = code.decode("ascii", errors="ignore")
                result["order_code"] = str(code).strip("\x00 ")
                # Determine series from order code
                result["series"] = self._identify_series_from_order_code(result["order_code"])
        except Exception as e:
            error_msg = str(e).strip("b'\" ")
            errors.append(f"order_code: {error_msg}")
            self.logger.debug(f"Order code method failed: {error_msg}")

        # Method 2: SZL 0x001C for additional details (if available)
        if not result["version"]:
            self.logger.debug("Firmware method 2: SZL 0x001C...")
            try:
                data = connection.read_szl(0x001C, 1)
                parsed = SZLParser._parse_0x001c(bytes(data), 1)
                if not result["order_code"] and parsed.get("order_code"):
                    result["order_code"] = parsed["order_code"]
            except Exception as e:
                error_msg = str(e).strip("b'\" ")
                errors.append(f"SZL: {error_msg}")
                self.logger.debug(f"SZL 0x001C method failed: {error_msg}")

        # Method 3: CPU info for series and serial (if not already found)
        self.logger.debug("Firmware method 3: CPU info...")
        try:
            cpu = connection.get_cpu_info()
            if not result["series"]:
                # ModuleTypeName is a ctypes c_char_Array -> bytes at runtime, and
                # lookup_s7_series() does str.startswith against it, raising
                # TypeError. That raise happens BEFORE the serial assignment
                # below and is swallowed by this block's except, so a real PLC
                # lost both the series AND the serial. The sibling _get_cpu_info
                # decodes before the same lookup; do the same here.
                result["series"] = lookup_s7_series(decode_s7_field(cpu.ModuleTypeName))
            result["serial"] = decode_s7_field(cpu.SerialNumber)
        except Exception as e:
            error_msg = str(e).strip("b'\" ")
            errors.append(f"CPU info: {error_msg}")
            self.logger.debug(f"CPU info method failed: {error_msg}")

        if result["version"]:
            self.logger.debug("Firmware version: %s", result["version"])

        # If no firmware info could be retrieved, report why
        if not result["version"] and not result["order_code"]:
            result["error"] = (
                "Could not retrieve firmware info - " + "; ".join(errors)
                if errors
                else "Access denied or unsupported device"
            )
            self.logger.warning(f"Firmware detection failed: {result['error']}")

        return result

    def _identify_series_from_order_code(self, order_code: str) -> str:
        """Identify S7 series from MLFB order code or module name

        Siemens Order Code Patterns:
        - 6ES7 21x: S7-1200 (211=1211C, 212=1212C, 214=1214C, 215=1215C, 217=1217C)
        - 6ES7 51x: S7-1500 (510=1510SP, 511=1511, 512=1512C, 513-518)
        - 6ES7 31x: S7-300 (312-319)
        - 6ES7 41x: S7-400 (410, 412, 414, 416, 417)
        - 6ES7 15x: ET200 distributed I/O (151=ET200S, 152=PN, 153=ET200M, 154=pro, 155=SP)
        - 6ES7 61x: SoftPLC/Virtual (611, 612, 616 PCI cards)
        - 6ED1: LOGO! logic modules
        """
        if not order_code:
            return "Unknown"
        code = order_code.upper().replace(" ", "")

        # Check for SoftPLC/Virtual PLC indicators in module name
        if "SOFTPLC" in code or "PLCSIM" in code:
            return "SoftPLC"
        if "OPC" in code or "IECP" in code.replace("_", ""):
            return "S7-CP"

        # LOGO! modules (6ED1)
        if "6ED1" in code:
            return "LOGO!"

        # Communication processors (6GK7) - CP343, CP443, etc.
        if "6GK7" in code:
            return "S7-CP"

        # S7 modules (6ES7)
        if "6ES7" in code:
            parts = code.split("-")
            if len(parts) >= 1:
                num_part = parts[0].replace("6ES7", "")

                # S7-1200 series (21x): 211, 212, 214, 215, 217
                if num_part.startswith("21"):
                    return "S7-1200"

                # S7-1200 compact (22x)
                elif num_part.startswith("22"):
                    return "S7-1200"

                # S7-1500 series (51x): 510, 511, 512, 513, 515, 516, 517, 518
                elif num_part.startswith("51"):
                    return "S7-1500"

                # S7-300 series (31x): 312, 313, 314, 315, 316, 317, 318, 319
                elif num_part.startswith("31"):
                    return "S7-300"

                # S7-400 series (41x): 410, 412, 414, 416, 417
                elif num_part.startswith("41"):
                    return "S7-400"

                # ET200 distributed I/O modules (15x)
                elif num_part.startswith("15"):
                    if len(num_part) >= 3:
                        suffix = num_part[2]
                        if suffix in "12":
                            return "ET200S"
                        elif suffix == "3":
                            return "ET200M"
                        elif suffix == "4":
                            return "ET200pro"
                        elif suffix == "5":
                            return "ET200SP"
                    return "ET200"

                # SoftPLC/PCI cards (61x): 611, 612, 616
                elif num_part.startswith("61"):
                    return "SoftPLC"

                # S7-200 legacy (2xx but not 21x/22x)
                elif (
                    num_part.startswith("2")
                    and not num_part.startswith("21")
                    and not num_part.startswith("22")
                ):
                    return "S7-200"

        return "Unknown"
