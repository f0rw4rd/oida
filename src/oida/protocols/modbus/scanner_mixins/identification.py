"""
Modbus Scanner Identification Mixin

Handles device identification operations:
- Server info retrieval and caching
- MEI Device Identification (FC 43/14) with pagination
- MEI response parsing
- Exception Status (FC 7)
- Server ID / Report Server ID (FC 17)
- Raw MEI fallback via socket
"""

from __future__ import annotations

import struct
from datetime import datetime
from typing import Any, Dict, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


class ScannerIdentificationMixin(_ScannerBase):
    """Mixin providing device identification for ModbusScanner."""

    def _get_server_info(self, client: Any) -> Dict[str, Any]:
        """Get basic server information (cached after first call)"""

        # Return cached if available
        if hasattr(self, "_cached_server_info") and self._cached_server_info:
            return self._cached_server_info

        conn_type = "TCP" if not self.serial_port else "RTU"
        self.logger.debug(f"Connection type: {conn_type}")

        info = {
            "connection_type": conn_type,
            "connected": True,
            "timestamp": datetime.now().isoformat(),
        }

        # Try to get server ID (function code 17)
        self.logger.debug("Reading Server ID (FC 17)...")
        server_id_info = self.read_server_id(client)
        if server_id_info:
            info["server_id"] = server_id_info
            self.logger.debug(f"Server ID retrieved: {server_id_info.get('identifier', 'N/A')}")
        else:
            self.logger.debug("Server ID not available (FC 17 not supported)")

        # Try MEI Device Identification (FC 43/14) if enabled
        if self.get_device_id:
            self.logger.debug("Reading MEI Device Identification (FC 43/14)...")
            device_id = self._read_device_identification(client)
            if device_id:
                info["device_identification"] = device_id
                # Extract key fields for easier access
                if "VendorName" in device_id:
                    info["vendor"] = device_id["VendorName"]
                if "ProductName" in device_id:
                    info["product"] = device_id["ProductName"]
                if "MajorMinorRevision" in device_id:
                    info["version"] = device_id["MajorMinorRevision"]
                self.logger.debug(
                    f"MEI Device ID: {info.get('vendor', 'Unknown')} - {info.get('product', 'Unknown')}"
                )
            else:
                self.logger.debug("MEI Device Identification not available")

        # Cache for subsequent calls
        self._cached_server_info = info
        return info

    def _read_device_identification(
        self,
        client: Any,
        mei_object: Optional[str] = None,
        mei_object_id: Optional[int] = None,
    ) -> Optional[Dict[str, str]]:
        """
        Read MEI Device Identification (Function Code 43, MEI Type 14)

        This implements the Modbus Encapsulated Interface for reading
        device identification objects as defined in the Modbus specification.

        Args:
            client: Modbus client connection
            mei_object: Category to read - "basic", "regular", "extended", "specific", or "all"
                       (default: "all" = read all three levels)
            mei_object_id: Specific object ID (0x00-0xFF) for "specific" mode

        Returns:
            dict: Device identification objects (VendorName, ProductCode, etc.)
                  or None if not supported
        """
        from ..constants import (
            ModbusExceptionCode,
            MEIReadDeviceIdCode,
        )

        device_info = {}

        # Map mei_object to read codes
        if mei_object == "specific" and mei_object_id is not None:
            read_codes = [MEIReadDeviceIdCode.SPECIFIC]
            start_object_id = mei_object_id
        elif mei_object == "basic":
            read_codes = [MEIReadDeviceIdCode.BASIC]
            start_object_id = 0x00
        elif mei_object == "regular":
            read_codes = [MEIReadDeviceIdCode.REGULAR]
            start_object_id = 0x00
        elif mei_object == "extended":
            read_codes = [MEIReadDeviceIdCode.EXTENDED]
            start_object_id = 0x00
        else:
            # Default: "all" - try all three stream access levels
            read_codes = [
                MEIReadDeviceIdCode.BASIC,
                MEIReadDeviceIdCode.REGULAR,
                MEIReadDeviceIdCode.EXTENDED,
            ]
            start_object_id = 0x00

        for read_code in read_codes:
            try:
                # Handle pagination: MEI responses may span multiple requests
                current_object_id = start_object_id
                max_iterations = 10  # Prevent infinite loops

                for iteration in range(max_iterations):
                    # Use pymodbus built-in read_device_information method
                    result = client.read_device_information(
                        read_code=read_code,
                        object_id=current_object_id,
                        device_id=self.unit_id,
                    )

                    if result and not result.isError():
                        # Parse the response
                        objects = self._parse_mei_response(result)
                        if objects:
                            device_info.update(objects)
                            level_names = {
                                1: "Basic",
                                2: "Regular",
                                3: "Extended",
                                4: "Specific",
                            }
                            level = level_names.get(read_code, f"Code {read_code}")
                            self.logger.debug(
                                f"MEI Device ID ({level}): Found {len(objects)} objects "
                                f"(iteration {iteration + 1})"
                            )

                        # Check if more objects are available (pagination)
                        more_follows = getattr(result, "more_follows", False)
                        next_object_id = getattr(result, "next_object_id", 0)

                        if more_follows and next_object_id > current_object_id:
                            self.logger.debug(
                                f"MEI pagination: more_follows=True, next_object_id=0x{next_object_id:02X}"
                            )
                            current_object_id = next_object_id
                            continue  # Fetch next page
                        else:
                            break  # No more pages
                    else:
                        # Check exception code
                        exc_code = getattr(result, "exception_code", None)
                        if exc_code == ModbusExceptionCode.ILLEGAL_FUNCTION:
                            self.logger.debug("MEI not supported (Illegal Function)")
                            break
                        elif exc_code == ModbusExceptionCode.ILLEGAL_DATA_ADDRESS:
                            self.logger.debug(f"MEI read code {read_code} not supported")
                        break  # Exit pagination loop on error

            except Exception as e:
                self.logger.debug(f"MEI read failed for code {read_code}: {e}")
                # Try alternative method using raw socket if available
                try:
                    raw_result = self._read_mei_raw(client, read_code)
                    if raw_result:
                        device_info.update(raw_result)
                except Exception as e2:
                    self.logger.debug(f"Raw MEI read also failed: {e2}")

        if device_info:
            vendor = device_info.get("VendorName", "Unknown")
            product = device_info.get("ProductName", "Unknown")
            self.logger.debug(f"Device Identification: {vendor} - {product}")

        return device_info if device_info else None

    def _parse_mei_response(self, result: Any) -> Dict[str, str]:
        """Parse MEI Device ID response into dictionary"""
        from ..constants import MEI_OBJECT_NAMES

        objects = {}

        # pymodbus 3.x ReadDeviceInformationResponse exposes .information
        if hasattr(result, "information"):
            for obj_id, value in result.information.items():
                obj_name = MEI_OBJECT_NAMES.get(obj_id, f"Object_{obj_id:02X}")
                if isinstance(value, bytes):
                    objects[obj_name] = value.decode("utf-8", errors="replace").strip("\x00")
                else:
                    objects[obj_name] = str(value)
        elif hasattr(result, "objects"):
            # Alternative list-of-dicts format ({object_id, value})
            for obj in result.objects:
                obj_id = obj.get("object_id", 0)
                value = obj.get("value", b"")
                obj_name = MEI_OBJECT_NAMES.get(obj_id, f"Object_{obj_id:02X}")
                if isinstance(value, bytes):
                    objects[obj_name] = value.decode("utf-8", errors="replace").strip("\x00")
                else:
                    objects[obj_name] = str(value)

        return objects

    def read_exception_status(self, client: Any) -> Optional[int]:
        """
        Read Exception Status using Function Code 7.

        FC 7 returns an 8-bit status byte representing 8 internal coils
        or status outputs. The meaning of each bit is device-specific.

        Args:
            client: Modbus client connection

        Returns:
            Status byte (0-255) or None if not supported
        """
        from ..constants import ModbusExceptionCode

        try:
            result = client.read_exception_status(device_id=self.unit_id)

            if result and not result.isError():
                if hasattr(result, "status"):
                    return result.status
                return None
            else:
                exc_code = getattr(result, "exception_code", None)
                if exc_code == ModbusExceptionCode.ILLEGAL_FUNCTION:
                    self.logger.debug("FC 7 (Read Exception Status) not supported by device")
                else:
                    self.logger.debug(f"FC 7 returned exception: {exc_code}")
                return None

        except Exception as e:
            self.logger.debug(f"Failed to read exception status (FC 7): {e}")
            return None

    def read_server_id(self, client: Any) -> Optional[Dict[str, Any]]:
        """
        Read Server ID using Function Code 17 (Report Server ID).

        FC 17 returns device-specific identification including:
        - Server ID byte (device identifier)
        - Run indicator (0xFF=Running, 0x00=Stopped)
        - Additional data (device-specific, often ASCII strings)

        Args:
            client: Modbus client connection

        Returns:
            Dict with server_id, run_status, and additional_data, or None if not supported
        """
        from ..constants import ModbusExceptionCode

        try:
            result = client.report_device_id(device_id=self.unit_id)

            if result and not result.isError():
                info = {}

                if hasattr(result, "identifier") and result.identifier:
                    identifier = result.identifier
                    if isinstance(identifier, bytes) and len(identifier) >= 1:
                        clean_id = identifier.rstrip(b"\xff\x00")
                        id_str = clean_id.decode("ascii", errors="ignore").strip()
                        if id_str and id_str.isprintable():
                            info["identifier"] = id_str

                        info["identifier_hex"] = identifier.hex()
                        info["server_id"] = identifier[0]
                        info["server_id_hex"] = f"0x{identifier[0]:02X}"

                        if len(identifier) > 1:
                            additional = identifier[1:].rstrip(b"\xff\x00")
                            if additional:
                                info["additional_data_hex"] = additional.hex()
                                ascii_str = additional.decode("ascii", errors="ignore").strip(
                                    "\x00"
                                )
                                if ascii_str and ascii_str.isprintable():
                                    info["additional_data_ascii"] = ascii_str

                if hasattr(result, "status"):
                    info["run_status"] = "Running" if result.status else "Stopped"

                return info if info else None
            else:
                exc_code = getattr(result, "exception_code", None)
                if exc_code == ModbusExceptionCode.ILLEGAL_FUNCTION:
                    self.logger.debug("FC 17 (Report Server ID) not supported by device")
                else:
                    self.logger.debug(f"FC 17 returned exception: {exc_code}")
                return None

        except Exception as e:
            self.logger.debug(f"Failed to read server ID (FC 17): {e}")
            return None

    def _read_mei_raw(self, client: Any, read_code: int) -> Optional[Dict[str, str]]:
        """
        Read MEI using raw socket (fallback method)

        Manually construct and send the MEI request when pymodbus
        doesn't handle it properly. Handles pagination via more_follows flag.
        """
        from ..constants import MEI_OBJECT_NAMES, EXCEPTION_CODES

        # TODO: Replace raw client.socket access with pymodbus
        # ReadDeviceInformationRequest. This bypasses the library and breaks
        # if pymodbus changes its internal socket attribute. Re-test with
        # pymodbus >=3.8 -- the MEI pagination bug may be fixed upstream.
        if not hasattr(client, "socket") or client.socket is None:
            return None

        all_objects = {}
        current_object_id = 0x00
        transaction_id = 1
        max_iterations = 10  # Prevent infinite loops

        try:
            for iteration in range(max_iterations):
                # Build MEI request: FC=43, MEI Type=14, Read Code, Object ID
                request = struct.pack(">BBBB", 0x2B, 0x0E, read_code, current_object_id)

                # MBAP header for TCP: Transaction ID, Protocol ID, Length, Unit ID
                protocol_id = 0
                length = len(request) + 1  # request + unit ID
                mbap = struct.pack(">HHHB", transaction_id, protocol_id, length, self.unit_id)
                transaction_id += 1

                # Send request
                client.socket.send(mbap + request)

                # Receive response (with timeout)
                client.socket.settimeout(self.timeout)
                response = client.socket.recv(256)

                if len(response) < 8:
                    break

                # Parse MEI response (skip MBAP header)
                data = response[7:]  # Skip MBAP header

                if len(data) < 7:
                    break

                # Check function code
                fc = data[0]
                if fc == 0x2B:  # Normal response
                    more_follows = data[4] == 0xFF
                    next_object_id = data[5]
                    num_objects = data[6]

                    offset = 7

                    for _ in range(num_objects):
                        if offset + 2 > len(data):
                            break
                        obj_id = data[offset]
                        obj_len = data[offset + 1]
                        offset += 2

                        if offset + obj_len > len(data):
                            break

                        obj_value = data[offset : offset + obj_len]
                        offset += obj_len

                        obj_name = MEI_OBJECT_NAMES.get(obj_id, f"Object_{obj_id:02X}")
                        all_objects[obj_name] = obj_value.decode("utf-8", errors="replace").strip(
                            "\x00"
                        )

                    # Check for pagination
                    if more_follows and next_object_id > current_object_id:
                        self.logger.debug(
                            f"MEI raw pagination: more_follows=True, "
                            f"next_object_id=0x{next_object_id:02X}"
                        )
                        current_object_id = next_object_id
                        continue  # Fetch next page
                    else:
                        break  # No more pages

                elif fc == 0xAB:  # Exception response (0x2B + 0x80)
                    exc_code = data[1] if len(data) > 1 else 0
                    exc_name = EXCEPTION_CODES.get(exc_code, f"Unknown ({exc_code})")
                    self.logger.debug(f"MEI exception response: {exc_name}")
                    break
                else:
                    break  # Unknown response

            return all_objects if all_objects else None

        except TimeoutError:
            self.logger.debug("MEI raw read timed out")
            return all_objects if all_objects else None
        except Exception as e:
            self.logger.debug(f"MEI raw read error: {e}")
            return all_objects if all_objects else None
