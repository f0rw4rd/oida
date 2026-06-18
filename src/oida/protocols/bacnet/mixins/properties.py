"""
BACnet Properties Mixin

Handles property read/write operations and present value reading.
"""

import asyncio
import struct
from typing import Any, Dict, Optional

from ..constants import (
    _load_bacpypes3,
    CONTROL_POINT_TYPES,
    OBJECT_TYPE_NAMES,
    OBJECT_TYPES,
    resolve_object_type,
    resolve_property_name,
)


class PropertiesMixin:
    """Mixin providing BACnet property read/write operations."""

    def _handle_enumerate_properties(self):
        """Read all properties for each enumerated object"""
        if not self.objects:
            self.logger.warning("No objects to enumerate. Run --enumerate-objects first.")
            return

        for device_id, objects_by_type in self.objects.items():
            device_info = self.devices.get(device_id, {})
            address = device_info.get("address", self.host)

            self.logger.display(f"\n[Properties - Device {device_id}]")

            for obj_type_name, instances in objects_by_type.items():
                for instance in instances[:10]:
                    self.logger.display(f"\n  {obj_type_name}:{instance}")
                    try:
                        common_props = [
                            "objectName",
                            "description",
                            "presentValue",
                            "statusFlags",
                            "outOfService",
                            "units",
                            "minPresValue",
                            "maxPresValue",
                        ]

                        for prop in common_props:
                            try:
                                value = self._read_property(address, obj_type_name, instance, prop)
                                if value is not None:
                                    self.logger.display(f"    {prop}: {value}")
                            except Exception as e:
                                self.logger.debug(f"Property {prop} read failed: {e}")

                    except Exception as e:
                        self.logger.debug(f"Failed to read properties: {e}")

    def _handle_present_values(self):
        """Read present values of all discovered objects"""
        if not self.objects:
            self._handle_enumerate_objects()

        if not self.objects:
            return

        for device_id, objects_by_type in self.objects.items():
            device_info = self.devices.get(device_id, {})
            address = device_info.get("address", self.host)

            self.logger.display(f"\n[Present Values - Device {device_id}]")

            for obj_type_name, instances in objects_by_type.items():
                for instance in instances:
                    try:
                        name = self._read_property(address, obj_type_name, instance, "objectName")
                        value = self._read_property(
                            address, obj_type_name, instance, "presentValue"
                        )
                        units = self._read_property(address, obj_type_name, instance, "units")

                        display_name = name or f"{obj_type_name}:{instance}"
                        unit_str = f" {units}" if units else ""
                        self.logger.display(f"  {display_name}: {value}{unit_str}")

                    except Exception as e:
                        self.logger.debug(
                            f"Present value read failed for {obj_type_name}:{instance}: {e}"
                        )

    def _parse_read_spec(self, spec: str):
        """Parse a read spec 'objectType:instance:property' into resolved (obj_type, instance, prop).

        Returns (obj_type, instance, prop) or None on invalid format.
        """
        parts = spec.split(":")
        if len(parts) != 3:
            self.logger.fail("Invalid read spec. Format: objectType:instance:property")
            return None
        obj_type, instance_str, prop = parts
        obj_type = resolve_object_type(obj_type)
        prop = resolve_property_name(prop)
        return obj_type, int(instance_str), prop

    def _parse_write_spec(self, spec: str):
        """Parse a write spec 'objectType:instance:property:value'.

        Returns (obj_type, instance, prop, value_str) or None on invalid format.
        """
        parts = spec.split(":")
        if len(parts) != 4:
            self.logger.fail("Invalid write spec. Format: objectType:instance:property:value")
            return None
        obj_type, instance_str, prop, value_str = parts
        obj_type = resolve_object_type(obj_type)
        prop = resolve_property_name(prop)
        return obj_type, int(instance_str), prop, value_str

    def _get_first_device_address(self) -> str:
        """Return the address of the first discovered device, or self.host."""
        if self.devices:
            device_id = list(self.devices.keys())[0]
            return self.devices[device_id].get("address", self.host)
        return self.host

    def _handle_read(self):
        """Read a specific property"""
        try:
            parsed = self._parse_read_spec(self.args.read)
            if parsed is None:
                return
            obj_type, instance, prop = parsed
            address = self._get_first_device_address()

            value = self._read_property(address, obj_type, instance, prop)
            if value is not None:
                self.logger.success(f"{obj_type}:{instance}:{prop} = {value}")
            else:
                self.logger.warning(f"Could not read {obj_type}:{instance}:{prop}")

        except Exception as e:
            self.logger.debug(f"handle read failed: {e}")
            self.logger.fail(f"Read failed: {e}")

    def _handle_write(self):
        """Write a property value"""
        if not getattr(self.args, "confirm", False):
            self.logger.fail("Write operations require --confirm flag")
            return

        try:
            parsed = self._parse_write_spec(self.args.write)
            if parsed is None:
                return
            obj_type, instance, prop, value = parsed
            address = self._get_first_device_address()

            try:
                write_value = float(value)
                if write_value.is_integer():
                    write_value = int(write_value)
            except ValueError as e:
                self.logger.debug(f"handle write failed: {e}")
                write_value = value

            priority = getattr(self.args, "priority", None)

            success = self._write_property(address, obj_type, instance, prop, write_value, priority)
            if success:
                self.logger.success(f"Wrote {write_value} to {obj_type}:{instance}:{prop}")
            else:
                self.logger.fail(f"Write failed for {obj_type}:{instance}:{prop}")

        except Exception as e:
            self.logger.debug(f"handle write failed: {e}")
            self.logger.fail(f"Write failed: {e}")

    async def _bacpypes3_read_single_property(self, app, target_addr, timeout: float):
        """Read a single property using bacpypes3"""
        types = _load_bacpypes3()
        ReadPropertyRequest = types["ReadPropertyRequest"]
        ObjectIdentifier = types["ObjectIdentifier"]
        PropertyIdentifier = types["PropertyIdentifier"]
        CharacterString = types["CharacterString"]
        AbortPDU = types["AbortPDU"]
        ErrorPDU = types["ErrorPDU"]
        RejectPDU = types["RejectPDU"]
        Error = types["Error"]

        try:
            parsed = self._parse_read_spec(self.args.read)
            if parsed is None:
                return
            obj_type, instance, prop = parsed

            obj_type_lower = obj_type.lower()
            if obj_type_lower in OBJECT_TYPE_NAMES:
                obj_id = ObjectIdentifier((obj_type_lower, instance))
            else:
                try:
                    obj_type_id = int(obj_type)
                    obj_type_name = OBJECT_TYPES.get(obj_type_id, obj_type)
                    obj_id = ObjectIdentifier((obj_type_name, instance))
                except ValueError as e:
                    self.logger.debug(f"bacpypes3 read single property failed: {e}")
                    obj_id = ObjectIdentifier((obj_type, instance))

            request = ReadPropertyRequest(
                objectIdentifier=obj_id,
                propertyIdentifier=PropertyIdentifier(prop),
            )
            request.pduDestination = target_addr

            try:
                response = await asyncio.wait_for(app.request(request), timeout=timeout)
            except (asyncio.TimeoutError, TimeoutError) as e:
                self.logger.debug(f"bacpypes3 read single property failed: {e}")
                self.logger.fail(f"Timeout reading {obj_type}:{instance}:{prop}")
                return
            except BaseException as e:
                self.logger.debug(f"bacpypes3 read single property failed: {e}")
                self.logger.fail(f"Error reading {obj_type}:{instance}:{prop}: {e}")
                return

            if response and not isinstance(response, (AbortPDU, ErrorPDU, RejectPDU, Error)):
                if hasattr(response, "propertyValue"):
                    pv = response.propertyValue
                    value = None
                    if hasattr(pv, "cast_out"):
                        try:
                            value = pv.cast_out(CharacterString)
                        except BaseException as e:
                            self.logger.debug(f"bacpypes3 read single property failed: {e}")
                            pass
                    if value is None and hasattr(pv, "tagList"):
                        tags = list(pv.tagList)
                        if tags:
                            tag = tags[0]
                            if hasattr(tag, "tag_data"):
                                value = tag.tag_data.hex()
                    if value is None:
                        value = str(pv)
                    self.logger.success(f"{obj_type}:{instance}:{prop} = {value}")
            else:
                self.logger.warning(f"Could not read {obj_type}:{instance}:{prop}")

        except BaseException as e:
            self.logger.debug(f"bacpypes3 read single property failed: {e}")
            self.logger.fail(f"Read failed: {e}")

    async def _bacpypes3_read_present_values(
        self, app, target_addr, device_id: int, timeout: float
    ):
        """Read present values of enumerated objects using bacpypes3"""
        types = _load_bacpypes3()
        ReadPropertyRequest = types["ReadPropertyRequest"]
        ObjectIdentifier = types["ObjectIdentifier"]
        PropertyIdentifier = types["PropertyIdentifier"]
        CharacterString = types["CharacterString"]
        Unsigned = types["Unsigned"]
        Real = types["Real"]
        AbortPDU = types["AbortPDU"]
        ErrorPDU = types["ErrorPDU"]
        RejectPDU = types["RejectPDU"]
        Error = types["Error"]

        if device_id not in self.objects:
            self.logger.warning("No objects enumerated. Run with --enumerate-objects first.")
            return

        self.logger.display("\n[Present Values]")

        for type_name, instances in self.objects[device_id].items():
            if type_name not in CONTROL_POINT_TYPES and type_name != "device":
                continue

            for instance in instances[:10]:
                try:
                    obj_id = ObjectIdentifier((type_name, instance))

                    request = ReadPropertyRequest(
                        objectIdentifier=obj_id,
                        propertyIdentifier=PropertyIdentifier("presentValue"),
                    )
                    request.pduDestination = target_addr

                    try:
                        response = await asyncio.wait_for(
                            app.request(request), timeout=min(timeout, 3.0)
                        )
                    except (asyncio.TimeoutError, TimeoutError) as e:
                        self.logger.debug(f"bacpypes3 read present values failed: {e}")
                        continue
                    except BaseException as e:
                        self.logger.debug(f"bacpypes3 read present values failed: {e}")
                        continue

                    if response and not isinstance(
                        response, (AbortPDU, ErrorPDU, RejectPDU, Error)
                    ):
                        if hasattr(response, "propertyValue"):
                            pv = response.propertyValue
                            value = None

                            for cast_type in [Real, Unsigned, CharacterString]:
                                if hasattr(pv, "cast_out"):
                                    try:
                                        value = pv.cast_out(cast_type)
                                        break
                                    except BaseException as e:
                                        self.logger.debug(f"bacpypes3 read prese failed: {e}")
                                        continue

                            if value is None and hasattr(pv, "tagList"):
                                tags = list(pv.tagList)
                                if tags and hasattr(tags[0], "tag_data"):
                                    data = tags[0].tag_data
                                    if len(data) == 4:
                                        value = struct.unpack(">f", data)[0]
                                    elif len(data) <= 4:
                                        value = int.from_bytes(data, "big")

                            if value is not None:
                                self.logger.display(f"  {type_name}:{instance} = {value}")

                except BaseException as e:
                    self.logger.debug(f"bacpypes3 read present values failed: {e}")
                    continue

    def _read_property(self, address: str, obj_type: str, instance: int, prop: str) -> Any:
        """Read a BACnet property"""
        try:
            result = self.bacnet.read(f"{address} {obj_type} {instance} {prop}")
            return result
        except Exception as e:
            self.logger.debug(f"Read {obj_type}:{instance}:{prop} failed: {e}")
            return None

    def _write_property(
        self,
        address: str,
        obj_type: str,
        instance: int,
        prop: str,
        value: Any,
        priority: Optional[int] = None,
    ) -> bool:
        """Write a BACnet property"""
        try:
            if priority:
                self.bacnet.write(f"{address} {obj_type} {instance} {prop} {value} - {priority}")
            else:
                self.bacnet.write(f"{address} {obj_type} {instance} {prop} {value}")
            return True
        except Exception as e:
            self.logger.debug(f"Write failed: {e}")
            return False

    async def _bacpypes3_write_single_property(self, app, target_addr, timeout: float):
        """Write a single property using bacpypes3 (raw scan path)"""
        types = _load_bacpypes3()
        ObjectIdentifier = types["ObjectIdentifier"]
        PropertyIdentifier = types["PropertyIdentifier"]
        WritePropertyRequest = types["WritePropertyRequest"]
        AnyAtomic = types["AnyAtomic"]
        CharacterString = types["CharacterString"]
        Real = types["Real"]
        Unsigned = types["Unsigned"]
        AbortPDU = types["AbortPDU"]
        ErrorPDU = types["ErrorPDU"]
        RejectPDU = types["RejectPDU"]
        Error = types["Error"]

        if not getattr(self.args, "confirm", False):
            self.logger.fail("Write operations require --confirm flag")
            return

        try:
            parsed = self._parse_write_spec(self.args.write)
            if parsed is None:
                return
            obj_type, instance, prop, value_str = parsed

            obj_type_lower = obj_type.lower()
            if obj_type_lower in OBJECT_TYPE_NAMES:
                obj_id = ObjectIdentifier((obj_type_lower, instance))
            else:
                obj_id = ObjectIdentifier((obj_type, instance))

            # Parse value
            try:
                write_value = float(value_str)
            except ValueError:
                write_value = value_str

            priority = getattr(self.args, "priority", None)

            if isinstance(write_value, float):
                prop_value = AnyAtomic(Real(write_value))
            elif isinstance(write_value, str):
                prop_value = AnyAtomic(CharacterString(write_value))
            else:
                prop_value = AnyAtomic(Real(float(write_value)))

            kwargs = {
                "objectIdentifier": obj_id,
                "propertyIdentifier": PropertyIdentifier(prop),
                "propertyValue": prop_value,
            }
            if priority is not None:
                kwargs["priority"] = Unsigned(int(priority))

            request = WritePropertyRequest(**kwargs)
            request.pduDestination = target_addr

            try:
                response = await asyncio.wait_for(app.request(request), timeout=min(timeout, 5.0))

                if response is None or not isinstance(
                    response, (ErrorPDU, Error, AbortPDU, RejectPDU)
                ):
                    self.logger.success(f"Wrote {value_str} to {obj_type}:{instance}:{prop}")
                else:
                    self.logger.fail(f"Write rejected: {response}")

            except (asyncio.TimeoutError, TimeoutError):
                self.logger.warning(f"Write timeout for {obj_type}:{instance}:{prop}")
            except BaseException as e:
                self.logger.fail(f"Write error: {e}")

        except Exception as e:
            self.logger.fail(f"Write failed: {e}")

    async def _bacpypes3_read_property_multiple(
        self, app, target_addr, device_id: int, timeout: float
    ):
        """Read multiple properties in a single request using ReadPropertyMultiple.

        RPM is 10-100x faster than individual ReadProperty calls for bulk
        property enumeration. Falls back to single reads on error.
        """
        types = _load_bacpypes3()
        ReadPropertyMultipleRequest = types["ReadPropertyMultipleRequest"]
        ReadAccessSpecification = types["ReadAccessSpecification"]
        PropertyReference = types["PropertyReference"]
        ObjectIdentifier = types["ObjectIdentifier"]
        PropertyIdentifier = types["PropertyIdentifier"]
        AbortPDU = types["AbortPDU"]
        ErrorPDU = types["ErrorPDU"]
        RejectPDU = types["RejectPDU"]
        Error = types["Error"]
        CharacterString = types["CharacterString"]
        Real = types["Real"]
        Unsigned = types["Unsigned"]

        if device_id not in self.objects:
            self.logger.warning("No objects enumerated. Run with --enumerate-objects first.")
            return

        self.logger.display("\n[ReadPropertyMultiple - Batch Property Read]")

        total_read = 0
        total_failed = 0

        for type_name, instances in self.objects[device_id].items():
            if type_name not in CONTROL_POINT_TYPES and type_name != "device":
                continue

            for instance in instances[:20]:
                props_to_read = [
                    "objectName",
                    "presentValue",
                    "description",
                    "statusFlags",
                    "outOfService",
                    "units",
                ]

                try:
                    prop_refs = []
                    for prop in props_to_read:
                        try:
                            prop_refs.append(
                                PropertyReference(
                                    propertyIdentifier=PropertyIdentifier(prop),
                                )
                            )
                        except BaseException as e:
                            self.logger.debug(f"bacpypes3 read property multiple failed: {e}")
                            continue

                    if not prop_refs:
                        continue

                    obj_id = ObjectIdentifier((type_name, instance))
                    read_access = ReadAccessSpecification(
                        objectIdentifier=obj_id,
                        listOfPropertyReferences=prop_refs,
                    )

                    request = ReadPropertyMultipleRequest(
                        listOfReadAccessSpecs=[read_access],
                    )
                    request.pduDestination = target_addr

                    try:
                        response = await asyncio.wait_for(
                            app.request(request), timeout=min(timeout, 5.0)
                        )
                    except (asyncio.TimeoutError, TimeoutError):
                        self.logger.debug(f"RPM timeout for {type_name}:{instance}")
                        total_failed += 1
                        continue
                    except BaseException as e:
                        self.logger.debug(f"RPM error for {type_name}:{instance}: {e}")
                        total_failed += 1
                        continue

                    if response and not isinstance(
                        response, (AbortPDU, ErrorPDU, RejectPDU, Error)
                    ):
                        total_read += 1
                        if hasattr(response, "listOfReadAccessResults"):
                            for result in response.listOfReadAccessResults:
                                if hasattr(result, "listOfResults"):
                                    values = []
                                    for prop_result in result.listOfResults:
                                        prop_id = getattr(prop_result, "propertyIdentifier", "?")
                                        if hasattr(prop_result, "readResult"):
                                            rr = prop_result.readResult
                                            value = None
                                            if hasattr(rr, "propertyValue"):
                                                pv = rr.propertyValue
                                                for cast_type in [
                                                    CharacterString,
                                                    Real,
                                                    Unsigned,
                                                ]:
                                                    if hasattr(pv, "cast_out"):
                                                        try:
                                                            value = pv.cast_out(cast_type)
                                                            break
                                                        except BaseException as e:
                                                            self.logger.debug(f"Failed: {e}")
                                                            continue
                                                if value is None:
                                                    value = str(pv)
                                            elif hasattr(rr, "propertyAccessError"):
                                                value = f"[error: {rr.propertyAccessError}]"
                                            else:
                                                value = str(rr)
                                            values.append(f"{prop_id}={value}")
                                    if values:
                                        self.logger.display(
                                            f"  {type_name}:{instance} - {', '.join(values[:4])}"
                                        )
                        else:
                            self.logger.display(f"  {type_name}:{instance} - RPM response received")
                    else:
                        # RPM not supported, log and continue
                        if isinstance(response, (AbortPDU,)):
                            self.logger.debug(
                                "RPM not supported by device (abort). Falling back to single reads."
                            )
                            # Fall back to single reads for remaining
                            total_failed += 1
                            break
                        total_failed += 1

                except BaseException as e:
                    self.logger.debug(f"RPM batch error: {e}")
                    total_failed += 1

        self.logger.display(f"\n  RPM Summary: {total_read} objects read, {total_failed} failed")
        if total_failed > 0:
            self.logger.display(
                "  Tip: Some devices don't support RPM. Use --values for single reads."
            )

    def _read_all_properties(self, address: str, obj_type: str, instance: int) -> Dict[str, Any]:
        """Read all available properties for an object"""
        properties = {}
        common_props = [
            "objectName",
            "objectType",
            "description",
            "presentValue",
            "statusFlags",
            "eventState",
            "reliability",
            "outOfService",
            "units",
            "minPresValue",
            "maxPresValue",
            "resolution",
            "covIncrement",
            "timeDelay",
            "notificationClass",
            "highLimit",
            "lowLimit",
            "deadband",
            "limitEnable",
            "eventEnable",
            "ackedTransitions",
            "notifyType",
            "eventTimeStamps",
            "eventMessageTexts",
            "eventDetectionEnable",
            "relinquishDefault",
            "priorityArray",
            "currentCommandPriority",
            "activeText",
            "inactiveText",
            "polarity",
            "changeOfStateTime",
            "changeOfStateCount",
            "timeOfActiveTimeReset",
            "timeOfStateCountReset",
            "elapsedActiveTime",
            "minOffTime",
            "minOnTime",
            "alarmValue",
            "numberOfStates",
            "stateText",
        ]

        for prop in common_props:
            try:
                value = self._read_property(address, obj_type, instance, prop)
                if value is not None:
                    properties[prop] = value
            except Exception as e:
                self.logger.debug(f"Property read failed for {obj_type}:{instance}:{prop}: {e}")

        return properties
