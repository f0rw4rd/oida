"""
KNX Device Info Mixin

Handles device identification, firmware reading, and programming mode checks.
"""

from typing import Any, Dict, TYPE_CHECKING

if TYPE_CHECKING:
    from xknx import XKNX

from ..constants import _xknx_cls  # noqa: E402
from ..data import (
    get_vendor_name,
    normalize_descriptor,
    parse_bcu_type,
)


class DeviceInfoMixin:
    """Mixin providing deviceinfo operations."""

    async def _read_descriptor(self, p2p, errors: list) -> tuple:
        """Read device descriptor and return (desc_hex, mask_version) or (None, None)."""
        try:
            resp = await p2p.request(
                _xknx_cls.DeviceDescriptorRead(descriptor=0),
                _xknx_cls.DeviceDescriptorResponse,
            )
            payload = resp.payload if resp else None
            raw_value = getattr(payload, "value", None) or (payload if payload else None)
            if raw_value:
                desc_bytes = normalize_descriptor(raw_value)
                if desc_bytes:
                    desc_hex = desc_bytes.hex()
                    mask_version = (
                        f"{desc_bytes[0]:02x}{desc_bytes[1]:02x}" if len(desc_bytes) >= 2 else None
                    )
                    return desc_hex, mask_version, desc_bytes
        except Exception as e:
            errors.append(f"descriptor: {e}")
        return None, None, None

    async def _read_memory_field(self, p2p, mem_addr: int, count: int, label: str, errors: list):
        """Read a KNX memory range, returning bytes or None."""
        try:
            resp = await p2p.request(
                _xknx_cls.MemoryRead(address=mem_addr, count=count),
                _xknx_cls.MemoryResponse,
            )
            if resp and resp.payload and resp.payload.data:
                return resp.payload.data
        except Exception as e:
            errors.append(f"{label}: {e}")
        return None

    async def _read_device_info(self, knx: "XKNX", address: str) -> Dict[str, Any]:
        """Read comprehensive device information"""
        info = {
            "address": address,
            "descriptor": None,
            "mask_version": None,
            "manufacturer_id": None,
            "manufacturer_name": None,
            "serial": None,
            "app_program": None,
            "order_number": None,
            "errors": [],
        }

        try:
            self.logger.display(f"Reading device info from {address}")
            addr = _xknx_cls.IndividualAddress(address)
            mgmt = knx.management

            async with mgmt.connection(addr) as p2p:
                # Device Descriptor (mask version)
                desc_hex, mask_ver, _desc_bytes = await self._read_descriptor(p2p, info["errors"])
                if desc_hex:
                    info["descriptor"] = desc_hex
                    info["mask_version"] = mask_ver
                    self.logger.display(f"  Descriptor: {desc_hex}")

                # Manufacturer ID (memory 0x0104, 2 bytes)
                data = await self._read_memory_field(p2p, 0x0104, 2, "manufacturer", info["errors"])
                if data:
                    mfr_id = int.from_bytes(data, "big")
                    info["manufacturer_id"] = mfr_id
                    info["manufacturer_name"] = get_vendor_name(mfr_id)
                    self.logger.display(f"  Manufacturer: {info['manufacturer_name']} ({mfr_id})")

                # Serial Number (memory 0x010B, 6 bytes)
                data = await self._read_memory_field(p2p, 0x010B, 6, "serial", info["errors"])
                if data:
                    info["serial"] = data.hex()
                    self.logger.display(f"  Serial: {info['serial']}")

                # Application Program (memory 0x0106, 5 bytes)
                data = await self._read_memory_field(p2p, 0x0106, 5, "app_program", info["errors"])
                if data:
                    info["app_program"] = data.hex()
                    self.logger.display(f"  App Program: {info['app_program']}")

                # Order Number (memory 0x0100, 2 bytes)
                data = await self._read_memory_field(p2p, 0x0100, 2, "order_number", info["errors"])
                if data:
                    info["order_number"] = data.hex()
                    self.logger.display(f"  Order Number: {info['order_number']}")

        except Exception as e:
            self.logger.fail(f"Error reading device info from {address}: {e}")
            info["errors"].append(f"connection: {e}")

        return info

    async def _identify_device(self, knx: "XKNX", address: str) -> Dict[str, Any]:
        """
        Identify device using PropertyValueRead from Object 0 (Device Object).

        This method uses PropertyValueRead which works on more BCU types than MemoryRead.
        Falls back to MemoryRead if properties fail.

        Key properties (Object 0):
            PID 12: MANUFACTURER_ID (2 bytes)
            PID 11: SERIAL_NUMBER (6 bytes)
            PID 55: PRODUCT_ID
            PID 78: HARDWARE_TYPE
            PID 9: FIRMWARE_REVISION
            PID 15: ORDER_INFO
            PID 93: APP_VERSION
            PID 91: APPLICATION_ID
            PID 54: PROG_MODE (0/1)
            PID 53: ERROR_FLAGS
            PID 56: MAX_APDU_LENGTH
            PID 16: PEI_TYPE
        """
        info = {
            "address": address,
            "manufacturer_id": None,
            "manufacturer_name": "Unknown",
            "serial_number": None,
            "product_id": None,
            "hardware_type": None,
            "firmware_revision": None,
            "order_info": None,
            "mask_version": None,
            "bcu_type": None,
            "descriptor": None,
            # New high-value properties
            "app_version": None,
            "application_id": None,
            "prog_mode": None,
            "error_flags": None,
            "max_apdu": None,
            "pei_type": None,
            "errors": [],
        }

        # Device properties to read from Object 0
        DEVICE_PROPS = {
            12: ("manufacturer_id", 2),  # 2 bytes - manufacturer code
            11: ("serial_number", 6),  # 6 bytes - serial number
            55: ("product_id", None),  # varies - product identifier
            78: ("hardware_type", None),  # varies - hardware type
            9: ("firmware_revision", None),  # varies - firmware version
            15: ("order_info", None),  # varies - order/model number
            # New high-value properties
            93: ("app_version", None),  # application version
            91: ("application_id", None),  # application identifier
            54: ("prog_mode", 1),  # 1 byte - programming mode (0/1)
            53: ("error_flags", 1),  # 1 byte - error flags
            56: ("max_apdu", 2),  # 2 bytes - max APDU length
            16: ("pei_type", 1),  # 1 byte - PEI type
        }

        try:
            self.logger.debug(f"Identifying device: {address}")
            addr = _xknx_cls.IndividualAddress(address)
            mgmt = knx.management

            async with mgmt.connection(addr) as p2p:
                # 1. Read Device Descriptor first (always works on responsive devices)
                desc_hex, mask_ver, desc_bytes = await self._read_descriptor(p2p, info["errors"])
                if desc_hex:
                    info["descriptor"] = desc_hex.upper()
                    if mask_ver:
                        info["mask_version"] = mask_ver.upper()
                    if desc_bytes:
                        info["bcu_type"] = self._parse_mask_version(desc_bytes)
                    self.logger.debug(f"  Descriptor: {info['descriptor']} -> {info['bcu_type']}")

                # 2. Read key properties from Object 0 using PropertyValueRead
                for pid, (key, expected_len) in DEVICE_PROPS.items():
                    try:
                        resp = await p2p.request(
                            _xknx_cls.PropertyValueRead(
                                object_index=0, property_id=pid, count=1, start_index=1
                            ),
                            _xknx_cls.PropertyValueResponse,
                        )
                        if resp and resp.payload and resp.payload.data:
                            data = resp.payload.data

                            if pid == 12:  # MANUFACTURER_ID
                                # 2 bytes big-endian
                                if len(data) >= 2:
                                    mfr_id = (data[0] << 8) | data[1]
                                elif len(data) == 1:
                                    mfr_id = data[0]
                                else:
                                    mfr_id = 0
                                info["manufacturer_id"] = mfr_id
                                info["manufacturer_name"] = get_vendor_name(mfr_id)
                                self.logger.debug(
                                    f"  Manufacturer: {info['manufacturer_name']} (ID: {mfr_id})"
                                )

                            elif pid == 11:  # SERIAL_NUMBER
                                info["serial_number"] = data.hex().upper()
                                self.logger.debug(f"  Serial: {info['serial_number']}")

                            elif pid == 54:  # PROG_MODE (0=OFF, 1=ON)
                                info["prog_mode"] = "ON" if data[0] != 0 else "OFF"
                                self.logger.debug(f"  Prog Mode: {info['prog_mode']}")

                            elif pid == 53:  # ERROR_FLAGS
                                info["error_flags"] = data[0] if data else 0
                                self.logger.debug(f"  Error Flags: {info['error_flags']}")

                            elif pid == 56:  # MAX_APDU_LENGTH
                                if len(data) >= 2:
                                    info["max_apdu"] = (data[0] << 8) | data[1]
                                else:
                                    info["max_apdu"] = data[0] if data else 0
                                self.logger.debug(f"  Max APDU: {info['max_apdu']}")

                            else:  # Other properties stored as hex
                                info[key] = data.hex().upper()
                                self.logger.debug(f"  {key}: {info[key]}")

                    except Exception as e:
                        info["errors"].append(f"PID {pid}: {e}")
                        self.logger.debug(f"  Property {pid} ({key}) read failed: {e}")

                # 3. Fallback: If manufacturer not found via property, try MemoryRead
                if info["manufacturer_id"] is None:
                    self.logger.debug(
                        "PropertyValueRead failed for manufacturer, trying MemoryRead fallback"
                    )
                    data = await self._read_memory_field(
                        p2p, 0x0104, 2, "manufacturer_fallback", info["errors"]
                    )
                    if data:
                        mfr_id = int.from_bytes(data, "big")
                        info["manufacturer_id"] = mfr_id
                        info["manufacturer_name"] = get_vendor_name(mfr_id)
                        self.logger.display(
                            f"  Manufacturer (memory): {info['manufacturer_name']} (ID: {mfr_id})"
                        )

                # 4. Fallback: Serial number from memory
                if info["serial_number"] is None:
                    data = await self._read_memory_field(
                        p2p, 0x010B, 6, "serial_fallback", info["errors"]
                    )
                    if data:
                        info["serial_number"] = data.hex().upper()
                        self.logger.display(f"  Serial (memory): {info['serial_number']}")

        except Exception as e:
            self.logger.fail(f"Error identifying device {address}: {e}")
            info["errors"].append(f"connection: {e}")

        return info

    def _parse_mask_version(self, desc_bytes: bytes) -> str:
        """Parse mask version bytes to BCU type string"""
        return parse_bcu_type(desc_bytes)

    def _display_device_info(self, info: Dict[str, Any]) -> None:
        """Display formatted device identification info"""
        addr = info.get("address", "Unknown")

        # Header
        self.logger.display(f"KNX Device: {addr}")
        self.logger.display(f"{'=' * 40}")

        # Manufacturer
        mfr_name = info.get("manufacturer_name", "Unknown")
        mfr_id = info.get("manufacturer_id")
        if mfr_id is not None:
            self.logger.display(f"  Manufacturer: {mfr_name} (ID: {mfr_id})")
        else:
            self.logger.display(f"  Manufacturer: {mfr_name}")

        # Serial number
        serial = info.get("serial_number")
        if serial:
            self.logger.display(f"  Serial:       {serial}")

        # Product ID
        product_id = info.get("product_id")
        if product_id:
            self.logger.display(f"  Product ID:   {product_id}")

        # Hardware type
        hw_type = info.get("hardware_type")
        if hw_type:
            self.logger.display(f"  Hardware:     {hw_type}")

        # Firmware
        fw_rev = info.get("firmware_revision")
        if fw_rev:
            self.logger.display(f"  Firmware:     {fw_rev}")

        # BCU Type
        bcu_type = info.get("bcu_type")
        mask_ver = info.get("mask_version")
        if bcu_type:
            if mask_ver:
                self.logger.display(f"  BCU Type:     {bcu_type} (Mask: 0x{mask_ver})")
            else:
                self.logger.display(f"  BCU Type:     {bcu_type}")

        # Order info
        order_info = info.get("order_info")
        if order_info:
            # Try to decode as ASCII if it looks like text
            try:
                decoded = bytes.fromhex(order_info).decode("ascii", errors="replace").strip()
                if decoded and decoded.isprintable():
                    self.logger.display(f"  Order Info:   {decoded} ({order_info})")
                else:
                    self.logger.display(f"  Order Info:   {order_info}")
            except Exception:
                self.logger.display(f"  Order Info:   {order_info}")

        # Application version
        app_ver = info.get("app_version")
        if app_ver:
            self.logger.display(f"  App Version:  {app_ver}")

        # Application ID
        app_id = info.get("application_id")
        if app_id:
            self.logger.display(f"  App ID:       {app_id}")

        # Programming mode
        prog_mode = info.get("prog_mode")
        if prog_mode is not None:
            if prog_mode == "ON":
                self.logger.warning(f"  Prog Mode:    {prog_mode}")
            else:
                self.logger.display(f"  Prog Mode:    {prog_mode}")

        # Error flags
        error_flags = info.get("error_flags")
        if error_flags is not None:
            if error_flags == 0:
                self.logger.display("  Error Flags:  None")
            else:
                self.logger.warning(f"  Error Flags:  0x{error_flags:02X}")

        # Max APDU length
        max_apdu = info.get("max_apdu")
        if max_apdu is not None:
            self.logger.display(f"  Max APDU:     {max_apdu} bytes")

        # PEI type
        pei_type = info.get("pei_type")
        if pei_type:
            self.logger.display(f"  PEI Type:     {pei_type}")

        # Check if we got any useful data
        useful_fields = [
            info.get("serial_number"),
            info.get("product_id"),
            info.get("hardware_type"),
            info.get("firmware_revision"),
            info.get("bcu_type"),
            info.get("order_info"),
        ]
        has_useful_data = any(f is not None for f in useful_fields)
        has_manufacturer = info.get("manufacturer_id") is not None

        if not has_useful_data and not has_manufacturer:
            self.logger.warning(
                "  No device data retrieved - device may not respond to property reads"
            )
            self.logger.display(
                "  Try: --firmware-info or --enumerate-objects for alternative methods"
            )

        # Errors
        errors = info.get("errors", [])
        if errors and self.debug:
            self.logger.debug(f"  Errors:       {len(errors)} property read failures")

    async def _read_firmware_info(self, knx: "XKNX", address: str) -> Dict[str, Any]:
        """Read firmware and BCU information from device"""
        self.logger.debug(f"Reading firmware info from {address}")
        info = {
            "address": address,
            "firmware_revision": None,
            "mask_version": None,
            "bcu_type": None,
            "hardware_type": None,
            "product_id": None,
            "order_info": None,
            "pei_type": None,
            "errors": [],
        }

        # Property IDs for Device Object (index 0)
        FIRMWARE_PROPS = {
            9: "firmware_revision",  # PID_FIRMWARE_REVISION
            78: "hardware_type",  # PID_HARDWARE_TYPE
            55: "product_id",  # PID_PRODUCT_ID
            15: "order_info",  # PID_ORDER_INFO
            16: "pei_type",  # PID_PEI_TYPE
        }

        try:
            self.logger.display(f"Reading firmware info from {address}")
            addr = _xknx_cls.IndividualAddress(address)
            mgmt = knx.management

            async with mgmt.connection(addr) as p2p:
                # Read device descriptor for mask version
                desc_hex, _mask_ver, desc_bytes = await self._read_descriptor(p2p, info["errors"])
                if desc_hex:
                    info["mask_version"] = desc_hex
                    info["bcu_type"] = self._parse_mask_version(desc_bytes)
                    self.logger.display(f"  Mask Version: {info['mask_version']}")
                    self.logger.display(f"  BCU Type: {info['bcu_type']}")

                # Read each firmware property
                for pid, key in FIRMWARE_PROPS.items():
                    try:
                        resp = await p2p.request(
                            _xknx_cls.PropertyValueRead(
                                object_index=0, property_id=pid, count=1, start_index=1
                            ),
                            _xknx_cls.PropertyValueResponse,
                        )
                        if resp and resp.payload and resp.payload.data:
                            info[key] = resp.payload.data.hex()
                            self.logger.display(f"  {key}: {info[key]}")
                    except Exception as e:
                        info["errors"].append(f"{key}: {e}")

        except Exception as e:
            self.logger.fail(f"Error reading firmware info from {address}: {e}")
            info["errors"].append(f"connection: {e}")

        return info

    async def _check_programming_mode(self, knx: "XKNX", address: str) -> Dict[str, Any]:
        """Check if device is in programming mode"""
        self.logger.debug(f"Checking programming mode for {address}")
        result = {
            "address": address,
            "programming_mode": None,
            "method": None,
            "error": None,
        }

        try:
            self.logger.display(f"Checking programming mode for {address}")
            addr = _xknx_cls.IndividualAddress(address)
            mgmt = knx.management

            async with mgmt.connection(addr) as p2p:
                # Try property read first (PID_PROGMODE = 54)
                try:
                    resp = await p2p.request(
                        _xknx_cls.PropertyValueRead(
                            object_index=0, property_id=54, count=1, start_index=1
                        ),
                        _xknx_cls.PropertyValueResponse,
                    )
                    if resp and resp.payload and resp.payload.data:
                        result["programming_mode"] = resp.payload.data[0] != 0
                        result["method"] = "property"
                        self.logger.display(
                            f"  Programming Mode (property): {result['programming_mode']}"
                        )
                except Exception as e:
                    self.logger.debug(
                        f"Failed to get resp: {e}"
                    )  # Fall through to memory read fallback

                # Fallback: memory read at 0x011A
                if result["method"] is None:
                    try:
                        resp = await p2p.request(
                            _xknx_cls.MemoryRead(address=0x011A, count=1), _xknx_cls.MemoryResponse
                        )
                        if resp and resp.payload and resp.payload.data:
                            result["programming_mode"] = resp.payload.data[0] != 0
                            result["method"] = "memory"
                            self.logger.display(
                                f"  Programming Mode (memory): {result['programming_mode']}"
                            )
                    except Exception as e:
                        result["error"] = str(e)

                # Report failure if neither method worked
                if result["method"] is None:
                    self.logger.fail(
                        "  Programming mode check failed: could not read property or memory"
                    )

        except Exception as e:
            result["error"] = str(e)
            self.logger.fail(f"Programming mode check failed: {e}")

        return result
