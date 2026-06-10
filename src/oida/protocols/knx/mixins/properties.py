"""
KNX Properties Mixin

Handles property read/write/fuzz, object enumeration, and vendor object discovery.
"""

import asyncio
from typing import Any, Dict, List, TYPE_CHECKING

import logging

logger = logging.getLogger(__name__)


if TYPE_CHECKING:
    from xknx import XKNX

from ..constants import _xknx_cls  # noqa: E402
from ..data import (
    OBJECT_TYPES,
    PROP_TYPE_MAP,
    get_object_type_name as get_obj_type_name,
    get_property_name as get_prop_name,
    get_data_type_name,
    get_vendor_name,
)
from ....utils import ProgressTracker
from ....utils.export_utils import print_table


class PropertiesMixin:
    """Mixin providing properties operations."""

    async def _read_property(
        self, knx: "XKNX", address: str, object_idx: int, property_id: int
    ) -> Dict[str, Any]:
        """Read interface object property"""
        self.logger.debug(f"PropertyValueRead: {address} obj={object_idx} pid={property_id}")
        result = {
            "address": address,
            "object_index": object_idx,
            "property_id": property_id,
            "data": None,
            "error": None,
        }

        try:
            self.logger.display(f"Reading property {object_idx}:{property_id} from {address}")
            addr = _xknx_cls.IndividualAddress(address)
            mgmt = knx.management

            async with mgmt.connection(addr) as p2p:
                resp = await p2p.request(
                    _xknx_cls.PropertyValueRead(
                        object_index=object_idx, property_id=property_id, count=1, start_index=1
                    ),
                    _xknx_cls.PropertyValueResponse,
                )
                if resp and resp.payload:
                    result["data"] = resp.payload.data.hex() if resp.payload.data else None
                    self.logger.success(f"  Property value: {result['data']}")

        except Exception as e:
            result["error"] = str(e)
            self.logger.debug(f"Error reading property: {e}")

        return result

    async def _write_property(self, knx: "XKNX", address: str, prop_arg: str) -> Dict[str, Any]:
        """Write raw bytes to interface object property"""
        self.logger.debug(f"PropertyValueWrite: {address} arg={prop_arg}")
        result = {
            "address": address,
            "object_index": None,
            "property_id": None,
            "data": None,
            "success": False,
            "error": None,
        }

        try:
            # Parse OBJ:PROP:DATA format
            parts = prop_arg.split(":")
            if len(parts) != 3:
                raise ValueError("Expected format: OBJ:PROP:HEXDATA (e.g., '0:78:00FA12')")

            obj_idx = int(parts[0])
            prop_id = int(parts[1])
            data = bytes.fromhex(parts[2])

            result["object_index"] = obj_idx
            result["property_id"] = prop_id
            result["data"] = parts[2].upper()

            # Safety check
            if not self.args.get("confirm"):
                self.logger.fail("--property-write requires --confirm flag (DANGEROUS operation)")
                result["error"] = "Missing --confirm flag"
                return result

            self.logger.display(
                f"Writing {len(data)} bytes to property {obj_idx}:{prop_id} on {address}"
            )
            addr = _xknx_cls.IndividualAddress(address)
            mgmt = knx.management

            async with mgmt.connection(addr) as p2p:
                _resp = await p2p.request(  # noqa: F841
                    _xknx_cls.PropertyValueWrite(
                        object_index=obj_idx, property_id=prop_id, count=1, start_index=1, data=data
                    ),
                    _xknx_cls.PropertyValueResponse,
                )
                result["success"] = True
                self.logger.success(
                    f"  Wrote {data.hex().upper()} to Object {obj_idx} Property {prop_id}"
                )

        except Exception as e:
            result["error"] = str(e)
            self.logger.fail(f"Error writing property: {e}")

        return result

    async def _fuzz_property(
        self, knx: "XKNX", address: str, prop_arg: str, iterations: int = 10
    ) -> Dict[str, Any]:
        """Fuzz a writable property"""
        import asyncio
        from ....utils.fuzzer import fuzz

        self.logger.debug(f"Fuzzing property: {address} arg={prop_arg}, iterations={iterations}")
        result = {
            "address": address,
            "object_index": None,
            "property_id": None,
            "success": False,
            "error": None,
        }

        try:
            parts = prop_arg.split(":")
            if len(parts) != 2:
                raise ValueError("Expected format: OBJ:PROP (e.g., '0:19')")

            obj_idx = int(parts[0])
            prop_id = int(parts[1])
            result["object_index"] = obj_idx
            result["property_id"] = prop_id

            if not self.args.get("confirm"):
                self.logger.fail("--fuzz-property requires --confirm flag (DANGEROUS operation)")
                result["error"] = "Missing --confirm flag"
                return result

            self.logger.warning(
                f"Fuzzing property {obj_idx}:{prop_id} on {address} - THIS MAY CAUSE DEVICE MALFUNCTION!"
            )

            addr = _xknx_cls.IndividualAddress(address)
            mgmt = knx.management

            async def read_property():
                async with mgmt.connection(addr) as p2p:
                    resp = await p2p.request(
                        _xknx_cls.PropertyValueRead(
                            object_index=obj_idx, property_id=prop_id, count=1, start_index=1
                        ),
                        _xknx_cls.PropertyValueResponse,
                    )
                    if resp and resp.payload and resp.payload.data:
                        return resp.payload.data
                    return b""

            async def write_property(data: bytes):
                async with mgmt.connection(addr) as p2p:
                    await p2p.request(
                        _xknx_cls.PropertyValueWrite(
                            object_index=obj_idx,
                            property_id=prop_id,
                            count=1,
                            start_index=1,
                            data=data,
                        ),
                        _xknx_cls.PropertyValueResponse,
                    )
                    return True

            # Read original value
            original = await read_property()
            successful, failed, anomalies, crashes = 0, 0, 0, 0

            for payload, _desc in fuzz(original, count=iterations):  # fuzz() yields (bytes, desc) tuples
                try:
                    if await write_property(payload):
                        successful += 1
                        readback = await read_property()
                        if readback != payload and readback != original:
                            anomalies += 1
                    else:
                        failed += 1
                except Exception:
                    crashes += 1
                await asyncio.sleep(0.2)

            # Restore original
            if original:
                await write_property(original)

            status = "+" if crashes == 0 and anomalies == 0 else "!"
            self.logger.display(
                f"  [{status}] {obj_idx}:{prop_id}: {successful + failed} tests, "
                f"{successful} writes, {anomalies} anomalies, {crashes} crashes"
            )

            result["success"] = True

        except Exception as e:
            result["error"] = str(e)
            self.logger.fail(f"Error fuzzing property: {e}")

        return result

    async def _read_property_description(
        self, knx: "XKNX", address: str, prop_arg: str
    ) -> Dict[str, Any]:
        """Read property description/metadata (access rights, max count, type)"""
        self.logger.debug(f"PropertyDescriptionRead: {address} arg={prop_arg}")
        result = {
            "address": address,
            "object_index": None,
            "property_id": None,
            "success": False,
            "error": None,
        }

        try:
            # Parse OBJ:PROP format
            parts = prop_arg.split(":")
            if len(parts) != 2:
                raise ValueError("Expected format: OBJ:PROP (e.g., '0:78')")

            obj_idx = int(parts[0])
            prop_id = int(parts[1])
            result["object_index"] = obj_idx
            result["property_id"] = prop_id

            self.logger.display(
                f"Reading property description for Object {obj_idx}, Property {prop_id}"
            )

            addr = _xknx_cls.IndividualAddress(address)
            mgmt = knx.management

            async with mgmt.connection(addr) as p2p:
                resp = await p2p.request(
                    _xknx_cls.PropertyDescriptionRead(
                        object_index=obj_idx, property_id=prop_id, property_index=0
                    ),
                    _xknx_cls.PropertyDescriptionResponse,
                )

                if resp and resp.payload:
                    payload = resp.payload
                    result["type"] = getattr(payload, "type_", None)
                    result["max_count"] = getattr(payload, "max_count", None)
                    result["access"] = getattr(payload, "access", None)

                    # Decode access rights
                    if result["access"] is not None:
                        read_level = (result["access"] >> 4) & 0x0F
                        write_level = result["access"] & 0x0F
                        result["read_level"] = read_level
                        result["write_level"] = write_level
                        result["writable"] = write_level < 15  # 15 = no write access

                    result["success"] = True

                    # Display results
                    self.logger.success("  Property Description:")
                    self.logger.display(f"    Type: {result.get('type', 'N/A')}")
                    self.logger.display(f"    Max Count: {result.get('max_count', 'N/A')}")
                    self.logger.display(f"    Read Level: {result.get('read_level', 'N/A')}")
                    self.logger.display(f"    Write Level: {result.get('write_level', 'N/A')}")
                    if result.get("writable"):
                        self.logger.warning("    WRITABLE: Yes")
                    else:
                        self.logger.display("    Writable: No")
                else:
                    result["error"] = "No response or empty payload"
                    self.logger.fail("  No property description available")

        except Exception as e:
            result["error"] = str(e)
            self.logger.fail(f"Error reading property description: {e}")

        return result

    async def _read_adc(self, knx: "XKNX", address: str, channel: int) -> Dict[str, Any]:
        """Read ADC channel value"""
        self.logger.debug(f"ADC read: device={address}, channel={channel}")
        result = {
            "address": address,
            "channel": channel,
            "value": None,
            "error": None,
        }

        try:
            self.logger.display(f"Reading ADC channel {channel} from {address}")
            addr = _xknx_cls.IndividualAddress(address)
            mgmt = knx.management

            async with mgmt.connection(addr) as p2p:
                resp = await p2p.request(
                    _xknx_cls.ADCRead(channel=channel, count=1), _xknx_cls.ADCResponse
                )
                if resp and resp.payload:
                    result["value"] = resp.payload.value
                    self.logger.success(f"  ADC value: {result['value']}")

        except Exception as e:
            result["error"] = str(e)
            self.logger.debug(f"Error reading ADC: {e}")

        return result

    async def _enumerate_objects(
        self, knx: "XKNX", address: str, max_objects: int = 42, read_properties: bool = True
    ) -> Dict[str, Any]:
        """
        Enumerate all interface objects on device (2024 reference style).

        Uses PropertyValueRead to read object type VALUE (not just description).
        Continues scanning even if an object doesn't exist (objects may not be contiguous).

        Args:
            knx: XKNX instance
            address: Individual address to query
            max_objects: Maximum objects to scan (default 42, KNX standard)
            read_properties: If True, reads property values for each object (slower but complete)
        """
        import struct
        import asyncio

        self.logger.debug(
            f"Enumerating objects on {address}, max={max_objects}, read_props={read_properties}"
        )
        result = {
            "address": address,
            "objects": [],
            "total_objects": 0,
            "total_properties": 0,
            "error": None,
        }

        try:
            self.logger.display(f"Enumerating interface objects on {address} (0-{max_objects - 1})")
            addr = _xknx_cls.IndividualAddress(address)
            mgmt = knx.management

            async with mgmt.connection(addr) as p2p:
                # First pass: discover all objects
                consecutive_failures = 0
                for obj_idx in range(max_objects):
                    # Throttle requests to avoid overwhelming the gateway
                    await asyncio.sleep(0.1)
                    try:
                        # Read object type VALUE (PID 1) - not just description
                        # This is how the 2024 reference code does it
                        resp = await p2p.request(
                            _xknx_cls.PropertyValueRead(
                                object_index=obj_idx,
                                property_id=1,  # PID_OBJECT_TYPE
                                count=1,
                                start_index=1,
                            ),
                            _xknx_cls.PropertyValueResponse,
                        )
                        if resp and resp.payload and resp.payload.data:
                            data = resp.payload.data
                            # Decode as UINT (big-endian)
                            if len(data) >= 2:
                                obj_type = struct.unpack(">H", data[:2])[0]
                            else:
                                obj_type = data[0]

                            obj_info = {
                                "index": obj_idx,
                                "type": obj_type,
                                "type_name": self._get_object_type_name(obj_type),
                                "properties": [],
                            }

                            result["objects"].append(obj_info)
                            self.logger.display(
                                f"  Object {obj_idx}: {obj_info['type_name']} (type {obj_type})"
                            )
                            consecutive_failures = 0  # Reset on success

                    except Exception as e:
                        # CONTINUE scanning - objects may not be contiguous
                        # (Changed from break - this is how 2024 reference works)
                        consecutive_failures += 1
                        self.logger.debug(f"  Object {obj_idx}: not accessible ({e})")
                        # Stop after 10 consecutive failures (likely reached end)
                        if consecutive_failures > 10:
                            self.logger.debug(
                                f"  Stopping scan after {consecutive_failures} consecutive failures"
                            )
                            break
                        continue

                result["total_objects"] = len(result["objects"])
                self.logger.display(f"Found {result['total_objects']} interface objects")

            # Second pass: read properties for each discovered object (new connection)
            if read_properties and result["objects"]:
                self.logger.display("")
                self.logger.display("Reading object properties...")
                self._print_access_legend()
                self.logger.display("")

                # Wait a bit before starting property reads
                await asyncio.sleep(0.5)

                for obj_info in result["objects"]:
                    obj_idx = obj_info["index"]
                    self.logger.display("")
                    self.logger.display(f"[Object {obj_idx}] {obj_info['type_name']}")

                    try:
                        # Create new connection for each object to avoid state issues
                        async with mgmt.connection(addr) as p2p_props:
                            try:
                                # Apply operation timeout to prevent hanging
                                properties = await asyncio.wait_for(
                                    self._enumerate_object_properties(
                                        p2p_props, obj_idx, max_props=100, delay_ms=150
                                    ),
                                    timeout=self.operation_timeout,
                                )
                            except asyncio.TimeoutError:
                                self.logger.warning(
                                    f"Timeout enumerating object {obj_idx} properties"
                                )
                                properties = []
                            obj_info["properties"] = properties
                            result["total_properties"] += len(properties)

                            # Display properties with values
                            for prop in properties:
                                pid = prop["property_id"]
                                name = prop["name"]
                                dtype = prop["data_type"]
                                values = prop["values"]
                                writeable = prop["writeable"]
                                read_lvl = prop["read_access"]
                                write_lvl = prop["write_access"]

                                # Format value display
                                if values:
                                    val_str = (
                                        values[0]
                                        if len(values) == 1
                                        else ":".join(str(v) for v in values)
                                    )
                                else:
                                    val_str = "(no data)"

                                line = self._format_property_line(
                                    obj_idx,
                                    pid,
                                    name,
                                    val_str,
                                    dtype,
                                    read_lvl,
                                    write_lvl,
                                    writeable,
                                )
                                self.logger.display(line)

                    except Exception as e:
                        self.logger.debug(f"    Error reading properties: {e}")

                    # Small delay between objects
                    await asyncio.sleep(0.3)

                self.logger.display("")
                self.logger.display(
                    f"Total: {result['total_objects']} objects, {result['total_properties']} properties"
                )

        except Exception as e:
            result["error"] = str(e)
            self.logger.fail(f"Error enumerating objects: {e}")

        return result

    async def _enumerate_object_properties(
        self, p2p, obj_idx: int, max_props: int = 255, delay_ms: int = 50
    ) -> List[Dict]:
        """
        Enumerate properties with VALUES (2024 reference style).

        Reads property descriptions AND actual values, decoding them based on data type.
        Includes access rights info (read/write levels, writeable flag).

        Args:
            p2p: P2P connection object
            obj_idx: Object index to enumerate
            max_props: Maximum property ID to scan (default 255)
            delay_ms: Delay between requests in milliseconds to avoid overwhelming device
        """
        import asyncio

        properties = []
        consecutive_failures = 0

        self.logger.debug(f"    Scanning properties 1-{max_props - 1}...")

        for prop_id in range(1, max_props):  # Start from 1, scan up to 255
            try:
                # Small delay between requests to avoid overwhelming the gateway
                if delay_ms > 0:
                    await asyncio.sleep(delay_ms / 1000.0)

                # Get property description first
                desc_resp = await p2p.request(
                    _xknx_cls.PropertyDescriptionRead(
                        object_index=obj_idx, property_id=prop_id, property_index=0
                    ),
                    _xknx_cls.PropertyDescriptionResponse,
                )
                if not desc_resp:
                    consecutive_failures += 1
                    if consecutive_failures > 20:
                        break
                    continue

                if not desc_resp.payload:
                    consecutive_failures += 1
                    if consecutive_failures > 20:
                        break
                    continue

                if desc_resp.payload.max_count == 0:
                    consecutive_failures += 1
                    # Stop scanning after 20 consecutive failures (reached end of properties)
                    if consecutive_failures > 20:
                        break
                    continue

                consecutive_failures = 0  # Reset on success
                payload = desc_resp.payload
                data_type = payload.type_ & 0x3F  # Extract data type (lower 6 bits)
                writeable = (payload.type_ >> 7) & 1  # Writeable flag (bit 7)
                read_access = payload.access >> 4  # Read access level (upper 4 bits)
                write_access = payload.access & 0x0F  # Write access level (lower 4 bits)

                # Read actual property VALUES
                values = []
                for idx in range(1, min(payload.max_count + 1, 5)):  # Limit to 5 values
                    try:
                        if delay_ms > 0:
                            await asyncio.sleep(delay_ms / 1000.0)

                        val_resp = await p2p.request(
                            _xknx_cls.PropertyValueRead(
                                object_index=obj_idx, property_id=prop_id, count=1, start_index=idx
                            ),
                            _xknx_cls.PropertyValueResponse,
                        )
                        if val_resp and val_resp.payload and val_resp.payload.data:
                            data = val_resp.payload.data
                            decoded = self._decode_property_value(data, data_type, prop_id)
                            values.append(decoded)
                    except Exception:
                        break  # Stop reading values on error

                properties.append(
                    {
                        "property_id": prop_id,
                        "name": self._get_property_name(obj_idx, prop_id),
                        "data_type": self._get_data_type_name(data_type),
                        "data_type_id": data_type,
                        "max_count": payload.max_count,
                        "writeable": writeable,
                        "read_access": read_access,
                        "write_access": write_access,
                        "values": values,
                    }
                )
            except Exception as e:
                consecutive_failures += 1
                self.logger.debug(f"    PID {prop_id} error: {e}")
                if consecutive_failures > 20:
                    break
                continue  # Continue scanning other properties

        return properties

    async def _discover_vendor_objects(self, knx: "XKNX", address: str) -> Dict[str, Any]:
        """Discover vendor-specific interface objects (indices 200-255)"""
        self.logger.debug(f"Scanning vendor objects (200-255) on {address}")
        result = {
            "address": address,
            "vendor_objects": [],
            "total_found": 0,
            "error": None,
        }

        try:
            self.logger.display(f"Discovering vendor objects on {address}")
            addr = _xknx_cls.IndividualAddress(address)
            mgmt = knx.management

            async with mgmt.connection(addr) as p2p:
                # Vendor objects typically at indices 200-255
                consecutive_failures = 0
                max_consecutive_failures = 5

                for obj_idx in range(200, 256):
                    try:
                        resp = await p2p.request(
                            _xknx_cls.PropertyDescriptionRead(
                                object_index=obj_idx, property_id=1, property_index=0
                            ),
                            _xknx_cls.PropertyDescriptionResponse,
                        )
                        if resp and resp.payload:
                            # Filter out false positives: type=0 with max_count<=1 and access=0
                            # means the object doesn't really exist
                            ptype = resp.payload.type_
                            max_count = getattr(resp.payload, "max_count", 0)
                            access = resp.payload.access

                            if ptype == 0 and max_count <= 1 and access == 0:
                                # Not a real object, skip
                                consecutive_failures += 1
                                continue

                            consecutive_failures = 0  # Reset on success
                            obj_info = {
                                "index": obj_idx,
                                "type": ptype,
                                "max_count": max_count,
                                "access": access,
                                "is_vendor_specific": True,
                                "name": None,
                            }

                            # Try to read object name (PID_OBJECT_NAME = 2)
                            try:
                                name_resp = await p2p.request(
                                    _xknx_cls.PropertyValueRead(
                                        object_index=obj_idx, property_id=2, count=1, start_index=1
                                    ),
                                    _xknx_cls.PropertyValueResponse,
                                )
                                if name_resp and name_resp.payload and name_resp.payload.data:
                                    obj_info["name"] = name_resp.payload.data.decode(
                                        "latin-1", errors="ignore"
                                    ).strip("\x00")
                            except Exception as e:
                                logger.debug(
                                    f"Failed to get name_resp: {e}"
                                )  # Name read is best-effort

                            result["vendor_objects"].append(obj_info)
                            self.logger.display(
                                f"  Vendor Object {obj_idx}: type={obj_info['type']}, name={obj_info['name']}"
                            )
                        else:
                            consecutive_failures += 1

                    except Exception as e:
                        consecutive_failures += 1
                        err_str = str(e).lower()
                        if (
                            "disconnect" in err_str
                            or "refused" in err_str
                            or "connection" in err_str
                        ):
                            self.logger.debug(f"Connection lost at object {obj_idx}: {e}")
                            break
                        await asyncio.sleep(0.1)

                    # Stop if too many failures (likely end of vendor objects)
                    if consecutive_failures >= max_consecutive_failures:
                        self.logger.debug(
                            f"Stopping scan after {max_consecutive_failures} consecutive failures"
                        )
                        break

                    # Delay between requests to avoid xknx race conditions
                    await asyncio.sleep(0.1)

                result["total_found"] = len(result["vendor_objects"])
                self.logger.display(f"Found {result['total_found']} vendor-specific objects")

        except Exception as e:
            result["error"] = str(e)
            # Only show error if we found nothing (connection likely failed early)
            if result["total_found"] == 0:
                self.logger.fail(f"Error discovering vendor objects: {e}")

        return result

    # =========================================================================
    # Phase 4: Advanced Features from 2024 Code
    # =========================================================================

    async def _dump_all_properties(
        self, knx: "XKNX", address: str, max_objects: int = 42, max_retries: int = 3
    ) -> Dict[str, Any]:
        """Dump all properties of all interface objects with retry on disconnect"""
        import struct

        self.logger.debug(f"Full property dump: device={address}, max_objects={max_objects}")
        result = {
            "address": address,
            "objects": [],
            "total_properties": 0,
            "failed_reads": 0,
            "error": None,
        }

        # Collect table data instead of immediate display
        table_data = []

        try:
            self.logger.display(f"Dumping all properties from {address}")
            self._print_access_legend()
            addr = _xknx_cls.IndividualAddress(address)
            mgmt = knx.management

            # First pass: discover all objects with progress tracking
            discovered_objects = []
            retries = 0
            obj_idx = 0
            discovery_progress = ProgressTracker(
                max_objects, threshold=2.0, interval=0.5, logger=self.logger
            )

            while obj_idx < max_objects:
                # Save position for reconnect - don't skip objects on disconnect
                resume_idx = obj_idx
                try:
                    async with mgmt.connection(addr) as p2p:
                        while obj_idx < max_objects:
                            discovery_progress.update(obj_idx, msg=f"Discovering object {obj_idx}")
                            try:
                                type_resp = await p2p.request(
                                    _xknx_cls.PropertyValueRead(
                                        object_index=obj_idx, property_id=1, count=1, start_index=1
                                    ),
                                    _xknx_cls.PropertyValueResponse,
                                )
                                if type_resp and type_resp.payload and type_resp.payload.data:
                                    data = type_resp.payload.data
                                    if len(data) >= 2:
                                        obj_type = struct.unpack(">H", data[:2])[0]
                                    else:
                                        obj_type = data[0] if data else 0
                                    obj_name = OBJECT_TYPES.get(obj_type, f"Unknown ({obj_type})")
                                    discovered_objects.append(
                                        {
                                            "index": obj_idx,
                                            "type": obj_type,
                                            "type_name": obj_name,
                                        }
                                    )
                                obj_idx += 1
                                resume_idx = obj_idx  # Update resume point after success
                                retries = 0  # Reset retries on success
                            except Exception as e:
                                if "disconnect" in str(e).lower():
                                    raise  # Re-raise to trigger reconnect
                                obj_idx += 1  # Object doesn't exist, continue
                                resume_idx = obj_idx
                except Exception as e:
                    if "disconnect" in str(e).lower() and retries < max_retries:
                        retries += 1
                        obj_idx = resume_idx  # Resume from last successful position
                        self.logger.warning(
                            f"Connection lost at obj {obj_idx}, reconnecting... (retry {retries}/{max_retries})"
                        )
                        await asyncio.sleep(1.0)
                        continue
                    elif retries >= max_retries:
                        self.logger.fail("Max retries reached during object discovery")
                        break
                    break

            self.logger.display(f"Found {len(discovered_objects)} objects, reading properties...")

            # Second pass: read properties for each object with progress tracking
            total_props_to_scan = len(discovered_objects) * 255
            prop_progress = ProgressTracker(
                total_props_to_scan, threshold=2.0, interval=1.0, logger=self.logger
            )
            props_scanned = 0

            for obj_num, obj_data in enumerate(discovered_objects):
                obj_idx = obj_data["index"]
                obj_type = obj_data["type"]
                obj_name = obj_data["type_name"]

                obj_info = {
                    "index": obj_idx,
                    "type": obj_type,
                    "type_name": obj_name,
                    "properties": [],
                }

                retries = 0
                prop_start = 1

                while prop_start < 256:
                    try:
                        async with mgmt.connection(addr) as p2p:
                            for prop_id in range(prop_start, 256):
                                props_scanned += 1
                                prop_progress.update(
                                    props_scanned,
                                    msg=f"Object {obj_idx} ({obj_num + 1}/{len(discovered_objects)})",
                                )

                                try:
                                    desc_resp = await p2p.request(
                                        _xknx_cls.PropertyDescriptionRead(
                                            object_index=obj_idx,
                                            property_id=prop_id,
                                            property_index=0,
                                        ),
                                        _xknx_cls.PropertyDescriptionResponse,
                                    )
                                    if (
                                        not desc_resp
                                        or not desc_resp.payload
                                        or desc_resp.payload.max_count == 0
                                    ):
                                        continue

                                    # Read property values
                                    values = []
                                    read_failed = False
                                    for val_idx in range(
                                        1, min(desc_resp.payload.max_count + 1, 10)
                                    ):
                                        try:
                                            val_resp = await p2p.request(
                                                _xknx_cls.PropertyValueRead(
                                                    object_index=obj_idx,
                                                    property_id=prop_id,
                                                    count=1,
                                                    start_index=val_idx,
                                                ),
                                                _xknx_cls.PropertyValueResponse,
                                            )
                                            if (
                                                val_resp
                                                and val_resp.payload
                                                and val_resp.payload.data
                                            ):
                                                values.append(val_resp.payload.data.hex())
                                        except Exception:
                                            read_failed = True
                                            break

                                    prop_name = (
                                        get_prop_name(obj_type, prop_id)
                                        if OBJECT_TYPES
                                        else f"PID_{prop_id}"
                                    )
                                    data_type = desc_resp.payload.type_ & 0x3F
                                    data_type_name = PROP_TYPE_MAP.get(
                                        data_type, f"TYPE_{data_type}"
                                    )
                                    read_lvl = desc_resp.payload.access >> 4
                                    write_lvl = desc_resp.payload.access & 0x0F
                                    writable = (desc_resp.payload.type_ >> 7) == 1

                                    prop_info = {
                                        "property_id": prop_id,
                                        "name": prop_name,
                                        "type": data_type,
                                        "type_name": data_type_name,
                                        "max_count": desc_resp.payload.max_count,
                                        "access_read": read_lvl,
                                        "access_write": write_lvl,
                                        "writable": writable,
                                        "values": values,
                                        "read_failed": read_failed,
                                    }
                                    obj_info["properties"].append(prop_info)
                                    result["total_properties"] += 1

                                    # Add to table data
                                    val_str = ":".join(values) if values else "(no data)"
                                    if read_failed:
                                        val_str = "(read failed)"
                                        result["failed_reads"] += 1
                                    table_data.append(
                                        [
                                            str(obj_idx),
                                            str(prop_id),
                                            prop_name[:22] if len(prop_name) > 22 else prop_name,
                                            val_str[:20] if len(val_str) > 20 else val_str,
                                            data_type_name,
                                            str(read_lvl),
                                            str(write_lvl),
                                            "W" if writable else "",
                                        ]
                                    )

                                    prop_start = prop_id + 1  # Track progress
                                    retries = 0

                                except Exception as e:
                                    if "disconnect" in str(e).lower():
                                        prop_start = prop_id  # Resume from this property
                                        raise
                                    # Track failed property read
                                    prop_name = (
                                        get_prop_name(obj_type, prop_id)
                                        if OBJECT_TYPES
                                        else f"PID_{prop_id}"
                                    )
                                    error_msg = str(e)[:18] if len(str(e)) > 18 else str(e)
                                    table_data.append(
                                        [
                                            str(obj_idx),
                                            str(prop_id),
                                            prop_name[:22] if len(prop_name) > 22 else prop_name,
                                            f"ERR: {error_msg}",
                                            "-",
                                            "-",
                                            "-",
                                            "",
                                        ]
                                    )
                                    result["failed_reads"] += 1
                                    continue

                            prop_start = 256  # Done with all properties

                    except Exception as e:
                        if "disconnect" in str(e).lower() and retries < max_retries:
                            retries += 1
                            self.logger.warning(
                                f"Connection lost at {obj_idx}:{prop_start}, reconnecting... (retry {retries}/{max_retries})"
                            )
                            await asyncio.sleep(1.0)
                            continue
                        break

                result["objects"].append(obj_info)
                await asyncio.sleep(0.3)  # Small delay between objects

            # Display table with all collected data
            if table_data:
                headers = ["Obj", "Prop", "Name", "Value", "Type", "R", "W", "Wr"]
                print_table(table_data, headers, f"Property Dump: {address}")

            # Summary
            failed_str = f", {result['failed_reads']} failed" if result["failed_reads"] > 0 else ""
            self.logger.display(
                f"Property dump complete: {len(result['objects'])} objects, {result['total_properties']} properties{failed_str}"
            )

        except Exception as e:
            result["error"] = str(e)
            self.logger.fail(f"Error dumping properties: {e}")

        return result

    def _get_object_type_name(self, obj_type: int) -> str:
        """Get interface object type name"""
        if obj_type >= 200:
            return f"Vendor-Specific ({obj_type})"
        return get_obj_type_name(obj_type)

    def _get_property_name(self, obj_idx: int, prop_id: int) -> str:
        """Get property name for a given object and property ID"""
        return get_prop_name(obj_idx, prop_id)

    def _get_data_type_name(self, data_type: int) -> str:
        """Get data type name from type ID"""
        return get_data_type_name(data_type)

    def _print_access_legend(self):
        """Print the access level legend for property output"""
        self.logger.display(
            "  Access levels: R=Read W=Write (0=system, 1-3=auth required, 15=free)"
        )

    def _format_property_line(
        self,
        obj_idx: int,
        prop_id: int,
        name: str,
        value: str,
        dtype: str,
        read_lvl: int,
        write_lvl: int,
        writable: bool,
    ) -> str:
        """Format a property line for consistent output across commands"""
        access_str = f"R:{read_lvl} W:{write_lvl}"
        if writable:
            access_str += " [writeable]"
        return f"    {obj_idx}:{prop_id:<3d} ({name:25s}): {value}  [{dtype}, {access_str}]"

    def _decode_property_value(self, data: bytes, data_type: int, prop_id: int) -> str:
        """
        Decode property value based on data type (from 2024 reference).

        Args:
            data: Raw bytes from PropertyValueRead
            data_type: Data type ID from property description (lower 6 bits)
            prop_id: Property ID for special handling
        """
        import struct

        if not data:
            return ""

        # Special property handling
        if prop_id == 12:  # MANUFACTURER_ID
            try:
                vendor_id = struct.unpack(">H", data[:2])[0] if len(data) >= 2 else data[0]
                return f"{get_vendor_name(vendor_id)} ({vendor_id})"
            except Exception as e:
                self.logger.debug(
                    f"Failed to get vendor_id: {e}"
                )  # Fall through to default hex format

        # Data type decoders (from 2024 knx_data_types)
        try:
            if data_type == 0x01:  # CHAR
                return repr(chr(data[0])) if data else ""
            elif data_type == 0x02:  # UNSIGNED_CHAR
                return str(data[0]) if data else "0"
            elif data_type == 0x03:  # INT (signed 16-bit)
                if len(data) >= 2:
                    return str(struct.unpack(">h", data[:2])[0])
            elif data_type == 0x04:  # UINT (unsigned 16-bit)
                if len(data) >= 2:
                    return str(struct.unpack(">H", data[:2])[0])
                elif len(data) == 1:
                    return str(data[0])
            elif data_type == 0x08:  # LONG (signed 32-bit)
                if len(data) >= 4:
                    return str(struct.unpack(">i", data[:4])[0])
            elif data_type == 0x09:  # ULONG (unsigned 32-bit)
                if len(data) >= 4:
                    return str(struct.unpack(">I", data[:4])[0])
            elif data_type == 0x0A:  # FLOAT
                if len(data) >= 4:
                    return f"{struct.unpack('>f', data[:4])[0]:.4f}"
            elif data_type == 0x0B:  # DOUBLE
                if len(data) >= 8:
                    return f"{struct.unpack('>d', data[:8])[0]:.6f}"
        except Exception as e:
            self.logger.debug(
                f"if data_type  0x01:   CHAR: {e}"
            )  # Fall through to default hex format

        # Default: return hex representation
        return data.hex().upper()

    def _parse_property_arg(self, prop_arg: str) -> tuple:
        """Parse property read argument (OBJ:PROP)"""
        try:
            parts = prop_arg.split(":")
            if len(parts) != 2:
                raise ValueError("Expected format: OBJ:PROP")

            obj_idx = int(parts[0])
            prop_id = int(parts[1])
            return obj_idx, prop_id
        except Exception as e:
            self.logger.fail(f"Invalid property format '{prop_arg}': {e}")
            return 0, 78  # Default: Device object, serial number
