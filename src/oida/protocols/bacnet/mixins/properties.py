"""
BACnet Properties Mixin

Handles property read/write operations and present value reading.
"""

import asyncio
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
        if not self.require_confirm("--confirm", detail="Write operations require --confirm flag"):
            self.results["success"] = False
            self.results["data"]["refused"] = "BACnet WriteProperty requires --confirm"
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
            except Exception as e:
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
                        except Exception as e:
                            self.logger.debug(f"bacpypes3 read single property failed: {e}")
                    if value is None:
                        value = str(pv)
                    self.logger.success(f"{obj_type}:{instance}:{prop} = {value}")
            else:
                self.logger.warning(f"Could not read {obj_type}:{instance}:{prop}")

        except Exception as e:
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
        ErrorRejectAbortNack = types["ErrorRejectAbortNack"]

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
                    # bacpypes3 raises Error/Reject/Abort (all ErrorRejectAbortNack
                    # subclasses) as BaseException, not Exception - must be caught
                    # explicitly or a single unsupported property (e.g. presentValue
                    # on a device/file/program/schedule object) crashes the scan.
                    except (Exception, ErrorRejectAbortNack) as e:
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
                                    except Exception as e:
                                        self.logger.debug(
                                            f"bacpypes3 read presentValue failed: {e}"
                                        )
                                        continue

                            if value is not None:
                                self.logger.display(f"  {type_name}:{instance} = {value}")

                except Exception as e:
                    self.logger.debug(f"bacpypes3 read present values failed: {e}")
                    continue

    async def _bacpypes3_read_one(
        self, app, target_addr, obj_type: str, instance: int, prop: str, timeout: float
    ) -> Any:
        """Read a single property over the live bacpypes3 ``app`` and decode it.

        The synchronous ``_read_property`` goes through ``self.bacnet`` (BAC0),
        which is ``None`` in the default bacpypes3 path. This is the app-based
        equivalent used by the raw-path dump.

        Two tiers:

        1. ``app.read_property`` -- bacpypes3 resolves the datatype from the
           object class and hands back a fully decoded value, so enumerations
           render symbolically (``active`` / ``quiet``) and constructed types
           (priorityArray, references, schedules) decode to JSON-friendly
           structures instead of opaque blobs.
        2. Raw ``ReadProperty`` + ``cast_out`` fallback for *custom / proprietary*
           types whose datatype bacpypes3 cannot resolve -- there tier 1 either
           raises or returns the ``-no object class-`` sentinel, so we decode the
           wire value with a best-effort primitive cast instead.

        Returns a JSON-serializable value, or ``None`` on timeout / error / an
        undecodable value.
        """
        try:
            value = await asyncio.wait_for(
                app.read_property(target_addr, f"{obj_type}:{instance}", prop),
                timeout=min(timeout, 3.0),
            )
            rendered = self._render_bacnet_value(value)
            if rendered is not None:
                return rendered
            # tier 1 produced nothing usable (AnyAtomic / -no object class-
            # sentinel for a proprietary type) -> fall through to the raw read.
        except (asyncio.TimeoutError, TimeoutError) as e:
            self.logger.debug(f"bacpypes3 read {obj_type}:{instance}:{prop} timed out: {e}")
            return None
        except Exception as e:
            # Unknown / proprietary property or object type, segmentation, etc.
            self.logger.debug(f"bacpypes3 read_property {obj_type}:{instance}:{prop}: {e}")

        return await self._bacpypes3_read_raw(app, target_addr, obj_type, instance, prop, timeout)

    def _render_bacnet_value(self, value) -> Any:
        """Turn a decoded bacpypes3 value into a JSON-serializable Python value.

        Handles the spread the dump sees: enumerations -> symbolic name,
        atomics -> native int/float/str, statusFlags -> named set bits,
        constructed types / arrays -> JSON. Returns ``None`` for values that
        could not be resolved (so the caller can drop to a raw read).
        """
        if value is None:
            return None

        from bacpypes3.primitivedata import Enumerated

        # Enumerated (BinaryPV, ShedState, LifeSafetyState, ...) subclasses int;
        # we want the symbolic label ("active"), not the raw ordinal.
        if isinstance(value, Enumerated):
            text = str(value).strip()
            return text or int(value)

        # statusFlags / similar BitStrings -> named flags ("in-alarm,fault").
        if type(value).__name__ == "StatusFlags":
            names = ["in-alarm", "fault", "overridden", "out-of-service"]
            try:
                set_flags = [n for n, b in zip(names, list(value)) if int(b)]
                return ",".join(set_flags) if set_flags else "normal"
            except Exception as e:
                self.logger.debug(f"statusFlags render failed: {e}")

        # CharacterString subclasses str; also catches bacpypes3's
        # "-no object class-" sentinel for object types it has no class for.
        if isinstance(value, str):
            text = value.strip()
            return None if text in ("-no object class-", "") else value

        # Real/Unsigned/Integer/Boolean subclass float/int -> use the native value.
        if isinstance(value, (bool, int, float)):
            return value

        # An AnyAtomic wrapper means bacpypes3 left it undecoded -> raw fallback.
        if type(value).__name__ == "AnyAtomic":
            return None

        # Constructed types (sequences/choices) and arrays -> JSON via bacpypes3.
        try:
            from bacpypes3.json import sequence_to_json

            return sequence_to_json(value)
        except Exception as e:
            self.logger.debug(f"sequence_to_json failed: {e}")

        if isinstance(value, (list, tuple)):
            rendered = []
            for element in value:
                rendered.append(self._render_bacnet_value(element))
            return rendered

        text = str(value).strip()
        return text or None

    async def _bacpypes3_read_raw(
        self, app, target_addr, obj_type: str, instance: int, prop: str, timeout: float
    ) -> Any:
        """Raw ReadProperty + cast_out -- the fallback for custom/proprietary types.

        bacpypes3 cannot type-resolve a proprietary object/property, so we read
        the wire value and best-effort cast it across primitive datatypes
        (OctetString -> hex). Never returns the opaque ``<Any object at 0x...>``
        repr -- an undecodable value yields ``None``.
        """
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

        try:
            request = ReadPropertyRequest(
                objectIdentifier=ObjectIdentifier((obj_type, instance)),
                propertyIdentifier=PropertyIdentifier(prop),
            )
            request.pduDestination = target_addr
            response = await asyncio.wait_for(app.request(request), timeout=min(timeout, 3.0))
        except (asyncio.TimeoutError, TimeoutError) as e:
            self.logger.debug(f"bacpypes3 raw read {obj_type}:{instance}:{prop} timed out: {e}")
            return None
        except Exception as e:
            self.logger.debug(f"bacpypes3 raw read {obj_type}:{instance}:{prop} failed: {e}")
            return None

        if not response or isinstance(response, (AbortPDU, ErrorPDU, RejectPDU, Error)):
            return None

        pv = getattr(response, "propertyValue", None)
        if pv is None or not hasattr(pv, "cast_out"):
            return None

        for cast_type in (Real, Unsigned, CharacterString):
            try:
                value = pv.cast_out(cast_type)
                if value is not None:
                    return value
            except Exception as e:
                self.logger.debug(f"bacpypes3 cast_out({cast_type.__name__}) failed: {e}")
                continue

        try:
            from bacpypes3.primitivedata import (
                Boolean,
                Date,
                Double,
                Enumerated,
                Integer,
                OctetString,
                Time,
            )

            broad_types = (Enumerated, Boolean, Integer, Double, Date, Time, OctetString)
        except Exception as e:
            self.logger.debug(f"bacpypes3 broad-type import failed: {e}")
            broad_types = ()

        for cast_type in broad_types:
            try:
                value = pv.cast_out(cast_type)
            except Exception as e:
                self.logger.debug(f"bacpypes3 cast_out({cast_type.__name__}) failed: {e}")
                continue
            if value is None:
                continue
            if cast_type is OctetString:
                try:
                    return bytes(value).hex()
                except Exception:
                    return str(value)
            return value

        # Undecodable / structured proprietary value: drop it rather than
        # emitting an opaque object repr.
        return None

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

        if not self.require_confirm("--confirm", detail="Write operations require --confirm flag"):
            self.results["success"] = False
            self.results["data"]["refused"] = "BACnet WriteProperty requires --confirm"
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

            # Parse value. Mirror the synchronous _handle_write path: demote
            # integer-valued floats to int so enumerations (e.g. binaryValue /
            # multistateValue presentValue) and integer properties are not sent
            # as Real, which a spec-compliant device rejects with a datatype error.
            try:
                write_value = float(value_str)
                if write_value.is_integer():
                    write_value = int(write_value)
            except ValueError:
                write_value = value_str

            priority = getattr(self.args, "priority", None)

            if isinstance(write_value, int):
                prop_value = AnyAtomic(Unsigned(write_value))
            elif isinstance(write_value, float):
                prop_value = AnyAtomic(Real(write_value))
            else:
                prop_value = AnyAtomic(CharacterString(write_value))

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
            except Exception as e:
                self.logger.fail(f"Write error: {e}")

        except Exception as e:
            self.logger.fail(f"Write failed: {e}")

    async def _bacpypes3_read_property_multiple(
        self, app, target_addr, device_id: int, timeout: float
    ):
        """Read multiple properties in a single request using ReadPropertyMultiple.

        RPM is 10-100x faster than individual ReadProperty calls for bulk
        property enumeration. Devices that abort RPM stop the probe with a
        tip to use --values (single reads) instead.
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
                        except Exception as e:
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
                    except Exception as e:
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
                                                        except Exception as e:
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
                        # RPM not supported by this device.
                        if isinstance(response, AbortPDU):
                            self.logger.debug(
                                "RPM not supported by device (abort); stopping RPM probe. "
                                "Use --values for single reads."
                            )
                            total_failed += 1
                            break
                        total_failed += 1

                except Exception as e:
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
