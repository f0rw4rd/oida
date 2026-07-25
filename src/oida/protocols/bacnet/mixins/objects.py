"""
BACnet Objects Mixin

Handles object and service enumeration.
"""

import asyncio
import struct
from ..constants import (
    _load_bacpypes3,
    OBJECT_TYPES,
)
from ..service_catalog import SERVICE_NAMES, by_name
from oida.utils.common_types import Category


def _is_callable(service_name: str) -> bool:
    spec = by_name(service_name)
    return bool(spec and spec.callable)


def _service_annotation(service_name: str) -> str:
    """Inline annotation for a device-advertised service: how OIDA can act on it."""
    spec = by_name(service_name)
    if spec is None:
        return ""
    if not spec.callable:
        if spec.risk == "indication":
            return "  (detect-only: device-emitted / not invokable on a target)"
        return "  (detect-only: no OIDA invoker yet)"
    token = spec.aliases[0] if spec.aliases else spec.name
    risk = {
        "read": "read",
        "write": "write — needs --confirm",
        "control": "CONTROL/disruptive — needs --confirm",
    }.get(spec.risk, spec.risk)
    return f"  → --call {token}  ({risk})"


class ObjectsMixin:
    """Mixin providing BACnet object and service enumeration."""

    def _handle_enumerate_objects(self):
        """List all objects on discovered devices"""
        if not self.devices:
            self.logger.warning("No devices to enumerate. Run --who-is first.")
            return

        max_objects = getattr(self.args, "max_objects", 1000)
        object_type_filter = getattr(self.args, "object_type", None)

        for device_id, device_info in self.devices.items():
            self.logger.display(f"\n[Objects - Device {device_id}]")
            try:
                address = device_info.get("address", self.host)

                # Read object list
                object_list = self._read_property(address, "device", device_id, "objectList")

                if not object_list:
                    self.logger.warning("  Could not read object list")
                    continue

                # Parse and categorize objects
                objects_by_type = {}
                object_count = 0

                for obj in object_list:
                    if object_count >= max_objects:
                        self.logger.warning(f"  Reached max objects limit ({max_objects})")
                        break

                    # Parse object identifier (type, instance)
                    obj_type, obj_instance = self._parse_object_id(obj)
                    obj_type_name = OBJECT_TYPES.get(obj_type, f"unknown-{obj_type}")

                    # Apply filter if specified
                    if object_type_filter:
                        if obj_type_name.lower() != object_type_filter.lower():
                            continue

                    if obj_type_name not in objects_by_type:
                        objects_by_type[obj_type_name] = []
                    objects_by_type[obj_type_name].append(obj_instance)
                    object_count += 1

                # Store and display results
                self.objects[device_id] = objects_by_type

                total_objects = sum(len(v) for v in objects_by_type.values())
                self.logger.success(f"  Found {total_objects} objects:")

                for obj_type_name, instances in sorted(objects_by_type.items()):
                    self.logger.display(f"    {obj_type_name}: {len(instances)} objects")

            except Exception as e:
                self.logger.debug(f"handle enumerate objects failed: {e}")
                self.logger.fail(f"Failed to enumerate objects: {e}")

    def _handle_services(self):
        """Enumerate supported BACnet services"""
        if not self.devices:
            self.logger.warning("No devices to query. Run --who-is first.")
            return

        for device_id, device_info in self.devices.items():
            self.logger.display(f"\n[Services - Device {device_id}]")
            try:
                address = device_info.get("address", self.host)

                # Read protocolServicesSupported
                services = self._read_property(
                    address, "device", device_id, "protocolServicesSupported"
                )
                if services:
                    device_info["services"] = services
                    self.logger.display(f"  Services: {services}")

                # Read protocolObjectTypesSupported
                obj_types = self._read_property(
                    address, "device", device_id, "protocolObjectTypesSupported"
                )
                if obj_types:
                    device_info["object_types"] = obj_types
                    self.logger.display(f"  Object Types: {obj_types}")

            except Exception as e:
                self.logger.debug(f"handle services failed: {e}")
                self.logger.fail(f"Failed to enumerate services: {e}")

    async def _bacpypes3_enumerate_objects(self, app, target_addr, device_id: int, timeout: float):
        """Enumerate objects using bacpypes3"""
        types = _load_bacpypes3()
        ReadPropertyRequest = types["ReadPropertyRequest"]
        ObjectIdentifier = types["ObjectIdentifier"]
        PropertyIdentifier = types["PropertyIdentifier"]
        AbortPDU = types["AbortPDU"]
        ErrorPDU = types["ErrorPDU"]
        RejectPDU = types["RejectPDU"]
        Error = types["Error"]

        self.logger.display("Enumerating objects...")

        try:
            request = ReadPropertyRequest(
                objectIdentifier=ObjectIdentifier(("device", device_id)),
                propertyIdentifier=PropertyIdentifier("objectList"),
            )
            request.pduDestination = target_addr

            try:
                response = await asyncio.wait_for(app.request(request), timeout=timeout)
            except (asyncio.TimeoutError, TimeoutError):
                self.logger.warning("Object enumeration timed out")
                return
            except BaseException as e:
                self.logger.warning(f"Object enumeration failed: {e}")
                return

            if response and not isinstance(response, (AbortPDU, ErrorPDU, RejectPDU, Error)):
                if hasattr(response, "propertyValue"):
                    pv = response.propertyValue
                    objects = []

                    # Handle bacpypes3 Any type with tagList
                    if hasattr(pv, "tagList"):
                        tag_list = pv.tagList
                        for tag in tag_list:
                            tag_str = str(tag)
                            if "open" in tag_str or "close" in tag_str:
                                continue
                            if "objectIdentifier" in tag_str:
                                if hasattr(tag, "tag_data"):
                                    data = tag.tag_data
                                    if len(data) >= 4:
                                        val = struct.unpack(">I", data[:4])[0]
                                        obj_type = (val >> 22) & 0x3FF
                                        obj_instance = val & 0x3FFFFF
                                        objects.append((obj_type, obj_instance))
                    elif hasattr(pv, "__iter__"):
                        for obj in pv:
                            if isinstance(obj, tuple):
                                objects.append(obj)
                            else:
                                obj_str = str(obj)
                                if "," in obj_str:
                                    parts = obj_str.split(",")
                                    objects.append((parts[0].strip(), int(parts[1].strip())))

                    if objects:
                        type_counts = {}
                        for obj_type, obj_instance in objects:
                            type_name = OBJECT_TYPES.get(obj_type, f"type-{obj_type}")
                            type_counts[type_name] = type_counts.get(type_name, 0) + 1

                            if device_id not in self.objects:
                                self.objects[device_id] = {}
                            if type_name not in self.objects[device_id]:
                                self.objects[device_id][type_name] = []
                            self.objects[device_id][type_name].append(obj_instance)

                        self.logger.success(f"Found {len(objects)} objects:")
                        for type_name, count in sorted(type_counts.items()):
                            self.logger.display(f"  {type_name}: {count}")
                    else:
                        self.logger.warning("Could not parse object list")
        except BaseException as e:
            self.logger.warning(f"Object enumeration error: {e}")

    async def _bacpypes3_enumerate_services(self, app, target_addr, device_id: int, timeout: float):
        """Enumerate supported BACnet services using bacpypes3"""
        types = _load_bacpypes3()
        ReadPropertyRequest = types["ReadPropertyRequest"]
        ObjectIdentifier = types["ObjectIdentifier"]
        PropertyIdentifier = types["PropertyIdentifier"]
        AbortPDU = types["AbortPDU"]
        ErrorPDU = types["ErrorPDU"]
        RejectPDU = types["RejectPDU"]
        Error = types["Error"]

        self.logger.display("[BACnet Services]")

        obj_id = ObjectIdentifier(("device", device_id))

        # Read protocolServicesSupported
        try:
            request = ReadPropertyRequest(
                objectIdentifier=obj_id,
                propertyIdentifier=PropertyIdentifier("protocolServicesSupported"),
            )
            request.pduDestination = target_addr

            try:
                response = await asyncio.wait_for(app.request(request), timeout=timeout)
            except BaseException as e:
                self.logger.debug(f"bacpypes3 enumerate services failed: {e}")
            else:
                if response and not isinstance(response, (AbortPDU, ErrorPDU, RejectPDU, Error)):
                    if hasattr(response, "propertyValue"):
                        pv = response.propertyValue
                        if hasattr(pv, "tagList"):
                            tags = list(pv.tagList)
                            data = None
                            for tag in tags:
                                tag_str = str(tag)
                                if "bitString" in tag_str and hasattr(tag, "tag_data"):
                                    data = tag.tag_data
                                    break
                            if data:
                                services = []
                                # Decode table is the catalog's ordered names, so
                                # detection and --call invocation never drift.
                                service_names = SERVICE_NAMES
                                for i, byte in enumerate(data[1:] if len(data) > 1 else data):
                                    for bit in range(8):
                                        if byte & (1 << (7 - bit)):
                                            idx = i * 8 + bit
                                            if idx < len(service_names):
                                                services.append(service_names[idx])
                                if services:
                                    self.logger.success(f"  Supported services: {len(services)}")
                                    for svc in services:
                                        self.logger.display(
                                            f"    - {svc}{_service_annotation(svc)}"
                                        )
                                    callable_here = [s for s in services if _is_callable(s)]
                                    if callable_here:
                                        self.logger.display(
                                            f"  {len(callable_here)} invokable via --call "
                                            "(see --list-services for syntax)"
                                        )
        except BaseException as e:
            self.logger.debug(f"Could not read services: {e}")

        # Read protocolObjectTypesSupported
        try:
            request = ReadPropertyRequest(
                objectIdentifier=obj_id,
                propertyIdentifier=PropertyIdentifier("protocolObjectTypesSupported"),
            )
            request.pduDestination = target_addr

            try:
                response = await asyncio.wait_for(app.request(request), timeout=timeout)
            except BaseException as e:
                self.logger.debug(f"bacpypes3 enumerate services failed: {e}")
            else:
                if response and not isinstance(response, (AbortPDU, ErrorPDU, RejectPDU, Error)):
                    if hasattr(response, "propertyValue"):
                        pv = response.propertyValue
                        if hasattr(pv, "tagList"):
                            tags = list(pv.tagList)
                            data = None
                            for tag in tags:
                                tag_str = str(tag)
                                if "bitString" in tag_str and hasattr(tag, "tag_data"):
                                    data = tag.tag_data
                                    break
                            if data:
                                obj_types = []
                                for i, byte in enumerate(data[1:] if len(data) > 1 else data):
                                    for bit in range(8):
                                        if byte & (1 << (7 - bit)):
                                            idx = i * 8 + bit
                                            type_name = OBJECT_TYPES.get(idx, f"type-{idx}")
                                            obj_types.append(type_name)
                                if obj_types:
                                    self.logger.success(
                                        f"  Supported object types: {len(obj_types)}"
                                    )
                                    for otype in obj_types:
                                        self.logger.display(f"    - {otype}")
        except BaseException as e:
            self.logger.debug(f"Could not read object types: {e}")

    async def _bacpypes3_deep_enum(self, app, target_addr, device_id: int, timeout: float):
        """Deep device walk: enumerate full object graph with cross-references.

        KNX-style deep enumeration that reads objectList via chunked/indexed
        reads, then walks each object to read key properties and follow
        cross-references to map device-to-device relationships.
        """
        types = _load_bacpypes3()
        ReadPropertyRequest = types["ReadPropertyRequest"]
        ObjectIdentifier = types["ObjectIdentifier"]
        PropertyIdentifier = types["PropertyIdentifier"]
        AbortPDU = types["AbortPDU"]
        ErrorPDU = types["ErrorPDU"]
        RejectPDU = types["RejectPDU"]
        Error = types["Error"]

        self.logger.display("\n[Deep Device Walk - Device {}]".format(device_id))

        device_obj_id = ObjectIdentifier(("device", device_id))
        error_types = (AbortPDU, ErrorPDU, RejectPDU, Error)
        req_timeout = min(timeout, 3.0)

        # --- Helper: read a single property, return raw response or None ---
        async def _read_prop(obj_id, prop_name, array_index=None):
            """Read a single property from the device, returning the response or None."""
            try:
                kwargs = {
                    "objectIdentifier": obj_id,
                    "propertyIdentifier": PropertyIdentifier(prop_name),
                }
                if array_index is not None:
                    kwargs["propertyArrayIndex"] = array_index
                request = ReadPropertyRequest(**kwargs)
                request.pduDestination = target_addr
                response = await asyncio.wait_for(app.request(request), timeout=req_timeout)
                if response and not isinstance(response, error_types):
                    return response
            except (asyncio.TimeoutError, TimeoutError) as e:
                self.logger.debug(f"read prop failed: {e}")
            except BaseException as e:
                self.logger.debug(f"Deep enum read {prop_name} failed: {e}")
            return None

        # --- Helper: extract a string value from a response ---
        def _extract_string(response):
            """Attempt to decode a character string from the response propertyValue."""
            if not hasattr(response, "propertyValue"):
                return None
            pv = response.propertyValue
            if hasattr(pv, "tagList"):
                for tag in pv.tagList:
                    if hasattr(tag, "tag_data") and tag.tag_data:
                        try:
                            return tag.tag_data.decode("utf-8", errors="replace").strip()
                        except BaseException as e:
                            self.logger.debug(f"extract string failed: {e}")
                            return tag.tag_data.hex()
            return str(pv)

        # --- Helper: extract an unsigned/integer value from a response ---
        def _extract_unsigned(response):
            """Attempt to extract an unsigned integer from the response propertyValue."""
            if not hasattr(response, "propertyValue"):
                return None
            pv = response.propertyValue
            if hasattr(pv, "tagList"):
                for tag in pv.tagList:
                    if hasattr(tag, "tag_data") and tag.tag_data and len(tag.tag_data) <= 4:
                        return int.from_bytes(tag.tag_data, "big")
            return None

        # --- Helper: extract a float value from a response ---
        def _extract_float(response):
            """Attempt to extract a float (real) from the response propertyValue."""
            if not hasattr(response, "propertyValue"):
                return None
            pv = response.propertyValue
            if hasattr(pv, "tagList"):
                for tag in pv.tagList:
                    if hasattr(tag, "tag_data") and tag.tag_data:
                        if len(tag.tag_data) == 4:
                            return struct.unpack(">f", tag.tag_data)[0]
                        elif len(tag.tag_data) <= 4:
                            return int.from_bytes(tag.tag_data, "big")
            return None

        # --- Helper: extract an object identifier (type, instance) from a response ---
        def _extract_object_id(response):
            """Extract a BACnet object identifier tuple from the response."""
            if not hasattr(response, "propertyValue"):
                return None
            pv = response.propertyValue
            if hasattr(pv, "tagList"):
                for tag in pv.tagList:
                    if hasattr(tag, "tag_data") and tag.tag_data and len(tag.tag_data) >= 4:
                        val = struct.unpack(">I", tag.tag_data[:4])[0]
                        obj_type = (val >> 22) & 0x3FF
                        obj_instance = val & 0x3FFFFF
                        return (obj_type, obj_instance)
            return None

        # --- Helper: extract a list of object identifiers from a response ---
        def _extract_object_id_list(response):
            """Extract a list of BACnet object identifier tuples from the response."""
            if not hasattr(response, "propertyValue"):
                return []
            pv = response.propertyValue
            results = []
            if hasattr(pv, "tagList"):
                for tag in pv.tagList:
                    tag_str = str(tag)
                    if "open" in tag_str or "close" in tag_str:
                        continue
                    if hasattr(tag, "tag_data") and tag.tag_data and len(tag.tag_data) >= 4:
                        val = struct.unpack(">I", tag.tag_data[:4])[0]
                        obj_type = (val >> 22) & 0x3FF
                        obj_instance = val & 0x3FFFFF
                        results.append((obj_type, obj_instance))
            return results

        # ===================================================================
        # Step 1: Read objectList length via indexed read (index 0 = length)
        # ===================================================================
        self.logger.display("  Reading object list (chunked/indexed)...")

        object_list = []
        resp = await _read_prop(device_obj_id, "objectList", array_index=0)
        list_length = 0
        if resp:
            list_length = _extract_unsigned(resp) or 0

        if list_length == 0:
            # Fallback: try reading the full objectList in one request
            self.logger.debug("  Index-0 returned 0; trying bulk objectList read")
            resp = await _read_prop(device_obj_id, "objectList")
            if resp and hasattr(resp, "propertyValue") and hasattr(resp.propertyValue, "tagList"):
                for tag in resp.propertyValue.tagList:
                    tag_str = str(tag)
                    if "open" in tag_str or "close" in tag_str:
                        continue
                    if hasattr(tag, "tag_data") and tag.tag_data and len(tag.tag_data) >= 4:
                        val = struct.unpack(">I", tag.tag_data[:4])[0]
                        obj_type = (val >> 22) & 0x3FF
                        obj_instance = val & 0x3FFFFF
                        object_list.append((obj_type, obj_instance))
            if not object_list:
                self.logger.warning("  Could not read objectList from device")
                return
        else:
            self.logger.display(f"  Object list length: {list_length}")
            max_objects = getattr(self.args, "max_objects", 1000)
            read_count = min(list_length, max_objects)
            if list_length > max_objects:
                self.logger.warning(
                    f"  Object list has {list_length} entries, limiting to {max_objects}"
                )

            for idx in range(1, read_count + 1):
                resp = await _read_prop(device_obj_id, "objectList", array_index=idx)
                if resp:
                    oid = _extract_object_id(resp)
                    if oid:
                        object_list.append(oid)
                    else:
                        self.logger.debug(f"  Could not parse objectList[{idx}]")
                else:
                    self.logger.debug(f"  No response for objectList[{idx}]")

        if not object_list:
            self.logger.warning("  No objects found in objectList")
            return

        self.logger.success(f"  Discovered {len(object_list)} objects in objectList")

        # ===================================================================
        # Step 2: Categorise objects by type
        # ===================================================================
        type_counts = {}
        for obj_type, obj_instance in object_list:
            type_name = OBJECT_TYPES.get(obj_type, f"type-{obj_type}")
            type_counts.setdefault(type_name, []).append(obj_instance)

        self.logger.display("\n  Object inventory:")
        for type_name in sorted(type_counts.keys()):
            instances = type_counts[type_name]
            self.logger.display(f"    {type_name}: {len(instances)}")

        # Store in self.objects for other methods
        if device_id not in self.objects:
            self.objects[device_id] = {}
        for type_name, instances in type_counts.items():
            self.objects[device_id][type_name] = instances

        # ===================================================================
        # Step 3: Walk each object — read key properties
        # ===================================================================
        self.logger.display("\n  Walking object properties...")

        key_props = [
            "objectName",
            "presentValue",
            "description",
            "statusFlags",
            "outOfService",
            "units",
        ]
        cross_ref_props = [
            "objectPropertyReference",
            "manipulatedVariableReference",
            "controlledVariableReference",
            "feedbackValue",
        ]

        inventory = []  # list of dicts for each object
        cross_references = []  # list of (source, ref_prop, target)
        structured_views = {}  # structuredView instance -> subordinate list

        objects_walked = 0
        max_walk = getattr(self.args, "max_objects", 500)

        for obj_type, obj_instance in object_list:
            if objects_walked >= max_walk:
                self.logger.warning(f"  Reached walk limit ({max_walk}), stopping property reads")
                break

            type_name = OBJECT_TYPES.get(obj_type, f"type-{obj_type}")
            obj_id = ObjectIdentifier((type_name, obj_instance))
            obj_info = {"type": type_name, "instance": obj_instance}

            # Read key properties
            for prop in key_props:
                resp = await _read_prop(obj_id, prop)
                if resp:
                    if prop == "objectName":
                        obj_info[prop] = _extract_string(resp)
                    elif prop == "presentValue":
                        fval = _extract_float(resp)
                        if fval is not None:
                            obj_info[prop] = fval
                        else:
                            sval = _extract_string(resp)
                            if sval:
                                obj_info[prop] = sval
                    elif prop == "description":
                        obj_info[prop] = _extract_string(resp)
                    elif prop == "statusFlags":
                        obj_info[prop] = _extract_string(resp)
                    elif prop == "outOfService":
                        uval = _extract_unsigned(resp)
                        obj_info[prop] = bool(uval) if uval is not None else _extract_string(resp)
                    elif prop == "units":
                        uval = _extract_unsigned(resp)
                        obj_info[prop] = uval if uval is not None else _extract_string(resp)

            # Follow cross-references
            for ref_prop in cross_ref_props:
                resp = await _read_prop(obj_id, ref_prop)
                if resp:
                    ref_oid = _extract_object_id(resp)
                    if ref_oid:
                        ref_type_name = OBJECT_TYPES.get(ref_oid[0], f"type-{ref_oid[0]}")
                        cross_references.append(
                            (
                                f"{type_name}:{obj_instance}",
                                ref_prop,
                                f"{ref_type_name}:{ref_oid[1]}",
                            )
                        )

            # Handle structuredView objects — read subordinateList
            if obj_type == 29:  # structuredView
                resp = await _read_prop(obj_id, "subordinateList")
                if resp:
                    subs = _extract_object_id_list(resp)
                    if subs:
                        sub_names = []
                        for sub_type, sub_inst in subs:
                            sub_type_name = OBJECT_TYPES.get(sub_type, f"type-{sub_type}")
                            sub_names.append(f"{sub_type_name}:{sub_inst}")
                        structured_views[obj_instance] = sub_names

            inventory.append(obj_info)
            objects_walked += 1

        # ===================================================================
        # Step 4: Display results
        # ===================================================================
        self.logger.display(f"\n  Walked {objects_walked} objects")

        # Show objects with names/values (first 30)
        named_objects = [o for o in inventory if o.get("objectName")]
        if named_objects:
            self.logger.display(f"\n  Named objects ({len(named_objects)} total):")
            for obj in named_objects[:30]:
                name = obj.get("objectName", "?")
                pv = obj.get("presentValue")
                units = obj.get("units")
                oos = obj.get("outOfService")

                detail_parts = []
                if pv is not None:
                    detail_parts.append(f"value={pv}")
                if units is not None:
                    detail_parts.append(f"units={units}")
                if oos:
                    detail_parts.append("OUT-OF-SERVICE")
                detail = ", ".join(detail_parts) if detail_parts else ""

                prefix = f"    {obj['type']}:{obj['instance']}"
                if detail:
                    self.logger.display(f"{prefix} '{name}' ({detail})")
                else:
                    self.logger.display(f"{prefix} '{name}'")

            if len(named_objects) > 30:
                self.logger.display(f"    ... and {len(named_objects) - 30} more named objects")

        # Show out-of-service objects as potential concerns
        oos_objects = [o for o in inventory if o.get("outOfService")]
        if oos_objects:
            self.logger.warning(f"\n  [!] {len(oos_objects)} object(s) are OUT-OF-SERVICE:")
            for obj in oos_objects[:10]:
                self.logger.display(
                    f"      {obj['type']}:{obj['instance']} '{obj.get('objectName', '?')}'"
                )

        # Show cross-references
        if cross_references:
            self.logger.display(f"\n  Cross-references ({len(cross_references)}):")
            for source, ref_prop, target in cross_references[:20]:
                self.logger.display(f"    {source} --[{ref_prop}]--> {target}")
            if len(cross_references) > 20:
                self.logger.display(f"    ... and {len(cross_references) - 20} more references")

        # Show structured view hierarchies
        if structured_views:
            self.logger.display(f"\n  Structured views ({len(structured_views)}):")
            for sv_instance, subordinates in structured_views.items():
                self.logger.display(f"    structuredView:{sv_instance}")
                for sub in subordinates[:10]:
                    self.logger.display(f"      +-- {sub}")
                if len(subordinates) > 10:
                    self.logger.display(f"      ... and {len(subordinates) - 10} more subordinates")

        # Summary
        self.logger.success(
            f"\n  Deep enum complete: {len(object_list)} objects, "
            f"{len(cross_references)} cross-refs, "
            f"{len(structured_views)} structured views"
        )

    async def _bacpypes3_enum_programs(self, app, target_addr, device_id: int, timeout: float):
        """Enumerate and analyze program objects (type 16) on the device.

        Reads program state, change mode, halt reasons, and location to
        assess active control logic and flag security concerns.
        """
        types = _load_bacpypes3()
        ReadPropertyRequest = types["ReadPropertyRequest"]
        ObjectIdentifier = types["ObjectIdentifier"]
        PropertyIdentifier = types["PropertyIdentifier"]
        AbortPDU = types["AbortPDU"]
        ErrorPDU = types["ErrorPDU"]
        RejectPDU = types["RejectPDU"]
        Error = types["Error"]

        self.logger.display("\n[Program Object Enumeration - Device {}]".format(device_id))

        error_types = (AbortPDU, ErrorPDU, RejectPDU, Error)
        req_timeout = min(timeout, 3.0)

        # --- Helper: read a single property, return raw response or None ---
        async def _read_prop(obj_id, prop_name):
            """Read a single property and return the response or None."""
            try:
                request = ReadPropertyRequest(
                    objectIdentifier=obj_id,
                    propertyIdentifier=PropertyIdentifier(prop_name),
                )
                request.pduDestination = target_addr
                response = await asyncio.wait_for(app.request(request), timeout=req_timeout)
                if response and not isinstance(response, error_types):
                    return response
            except (asyncio.TimeoutError, TimeoutError) as e:
                self.logger.debug(f"read prop failed: {e}")
            except BaseException as e:
                self.logger.debug(f"Program enum read {prop_name} failed: {e}")
            return None

        # --- Helper: extract a string value from a response ---
        def _extract_string(response):
            """Attempt to decode a character string from the response."""
            if not hasattr(response, "propertyValue"):
                return None
            pv = response.propertyValue
            if hasattr(pv, "tagList"):
                for tag in pv.tagList:
                    if hasattr(tag, "tag_data") and tag.tag_data:
                        try:
                            return tag.tag_data.decode("utf-8", errors="replace").strip()
                        except BaseException as e:
                            self.logger.debug(f"extract string failed: {e}")
                            return tag.tag_data.hex()
            return str(pv)

        # --- Helper: extract an unsigned/enum value from a response ---
        def _extract_unsigned(response):
            """Attempt to extract an unsigned integer from the response."""
            if not hasattr(response, "propertyValue"):
                return None
            pv = response.propertyValue
            if hasattr(pv, "tagList"):
                for tag in pv.tagList:
                    if hasattr(tag, "tag_data") and tag.tag_data and len(tag.tag_data) <= 4:
                        return int.from_bytes(tag.tag_data, "big")
            return None

        # BACnet programState enum values (clause 12.24.17)
        PROGRAM_STATES = {
            0: "idle",
            1: "loading",
            2: "running",
            3: "waiting",
            4: "halted",
            5: "unloading",
        }

        # BACnet programChange enum values (clause 12.24.18)
        PROGRAM_CHANGES = {
            0: "ready",
            1: "load",
            2: "run",
            3: "halt",
            4: "restart",
            5: "unload",
        }

        # ===================================================================
        # Step 1: Find all program objects
        # ===================================================================
        program_instances = []

        # Prefer already-enumerated objects
        if device_id in self.objects and "program" in self.objects[device_id]:
            program_instances = list(self.objects[device_id]["program"])
        else:
            # Try reading objectList to find program objects (type 16)
            self.logger.display("  No cached objects, probing for program objects...")
            device_obj_id = ObjectIdentifier(("device", device_id))

            # Read objectList length
            try:
                kwargs = {
                    "objectIdentifier": device_obj_id,
                    "propertyIdentifier": PropertyIdentifier("objectList"),
                    "propertyArrayIndex": 0,
                }
                request = ReadPropertyRequest(**kwargs)
                request.pduDestination = target_addr
                resp = await asyncio.wait_for(app.request(request), timeout=req_timeout)

                list_length = 0
                if resp and not isinstance(resp, error_types):
                    if hasattr(resp, "propertyValue") and hasattr(resp.propertyValue, "tagList"):
                        for tag in resp.propertyValue.tagList:
                            if hasattr(tag, "tag_data") and tag.tag_data and len(tag.tag_data) <= 4:
                                list_length = int.from_bytes(tag.tag_data, "big")
                                break

                if list_length > 0:
                    scan_limit = min(list_length, getattr(self.args, "max_objects", 1000))
                    for idx in range(1, scan_limit + 1):
                        try:
                            kwargs = {
                                "objectIdentifier": device_obj_id,
                                "propertyIdentifier": PropertyIdentifier("objectList"),
                                "propertyArrayIndex": idx,
                            }
                            req = ReadPropertyRequest(**kwargs)
                            req.pduDestination = target_addr
                            r = await asyncio.wait_for(app.request(req), timeout=req_timeout)
                            if r and not isinstance(r, error_types):
                                if hasattr(r, "propertyValue") and hasattr(
                                    r.propertyValue, "tagList"
                                ):
                                    for tag in r.propertyValue.tagList:
                                        if (
                                            hasattr(tag, "tag_data")
                                            and tag.tag_data
                                            and len(tag.tag_data) >= 4
                                        ):
                                            val = struct.unpack(">I", tag.tag_data[:4])[0]
                                            obj_type = (val >> 22) & 0x3FF
                                            obj_instance = val & 0x3FFFFF
                                            if obj_type == 16:  # program
                                                program_instances.append(obj_instance)
                                            break
                        except (asyncio.TimeoutError, TimeoutError) as e:
                            self.logger.debug(f"extract unsigned failed: {e}")
                            continue
                        except BaseException as e:
                            self.logger.debug(f"extract unsigned failed: {e}")
                            continue
                else:
                    # Fallback: try bulk objectList read
                    try:
                        req = ReadPropertyRequest(
                            objectIdentifier=device_obj_id,
                            propertyIdentifier=PropertyIdentifier("objectList"),
                        )
                        req.pduDestination = target_addr
                        r = await asyncio.wait_for(app.request(req), timeout=timeout)
                        if r and not isinstance(r, error_types):
                            if hasattr(r, "propertyValue") and hasattr(r.propertyValue, "tagList"):
                                for tag in r.propertyValue.tagList:
                                    tag_str = str(tag)
                                    if "open" in tag_str or "close" in tag_str:
                                        continue
                                    if (
                                        hasattr(tag, "tag_data")
                                        and tag.tag_data
                                        and len(tag.tag_data) >= 4
                                    ):
                                        val = struct.unpack(">I", tag.tag_data[:4])[0]
                                        obj_type = (val >> 22) & 0x3FF
                                        obj_instance = val & 0x3FFFFF
                                        if obj_type == 16:
                                            program_instances.append(obj_instance)
                    except BaseException as e:
                        self.logger.debug(f"Bulk objectList read failed: {e}")

            except (asyncio.TimeoutError, TimeoutError):
                self.logger.warning("  Timeout reading objectList for program discovery")
            except BaseException as e:
                self.logger.debug(f"Program discovery objectList read failed: {e}")

        if not program_instances:
            self.logger.display("  No program objects found on this device")
            return

        self.logger.display(f"  Found {len(program_instances)} program object(s)")

        # ===================================================================
        # Step 2: Read properties for each program object
        # ===================================================================
        programs = []
        security_concerns = []

        for instance in program_instances:
            obj_id = ObjectIdentifier(("program", instance))
            prog_info = {"instance": instance}

            # objectName
            resp = await _read_prop(obj_id, "objectName")
            if resp:
                prog_info["objectName"] = _extract_string(resp)

            # programState (enum: idle/loading/running/waiting/halted/unloading)
            resp = await _read_prop(obj_id, "programState")
            if resp:
                state_val = _extract_unsigned(resp)
                if state_val is not None:
                    prog_info["programState"] = PROGRAM_STATES.get(
                        state_val, f"unknown-{state_val}"
                    )
                else:
                    prog_info["programState"] = _extract_string(resp)

            # programChange (enum: ready/load/run/halt/restart/unload)
            resp = await _read_prop(obj_id, "programChange")
            if resp:
                change_val = _extract_unsigned(resp)
                if change_val is not None:
                    prog_info["programChange"] = PROGRAM_CHANGES.get(
                        change_val, f"unknown-{change_val}"
                    )
                else:
                    prog_info["programChange"] = _extract_string(resp)

            # reasonForHalt
            resp = await _read_prop(obj_id, "reasonForHalt")
            if resp:
                halt_val = _extract_unsigned(resp)
                if halt_val is not None:
                    halt_reasons = {
                        0: "normal",
                        1: "loadFailed",
                        2: "internal",
                        3: "program",
                        4: "other",
                    }
                    prog_info["reasonForHalt"] = halt_reasons.get(halt_val, f"unknown-{halt_val}")
                else:
                    prog_info["reasonForHalt"] = _extract_string(resp)

            # descriptionOfHalt
            resp = await _read_prop(obj_id, "descriptionOfHalt")
            if resp:
                prog_info["descriptionOfHalt"] = _extract_string(resp)

            # programLocation
            resp = await _read_prop(obj_id, "programLocation")
            if resp:
                prog_info["programLocation"] = _extract_string(resp)

            # instanceOf
            resp = await _read_prop(obj_id, "instanceOf")
            if resp:
                prog_info["instanceOf"] = _extract_string(resp)

            # Description
            resp = await _read_prop(obj_id, "description")
            if resp:
                prog_info["description"] = _extract_string(resp)

            programs.append(prog_info)

            # --- Security concern checks ---
            state = prog_info.get("programState", "")
            name = prog_info.get("objectName", f"program:{instance}")

            if state == "loading":
                security_concerns.append(
                    f"ACTIVE LOAD: '{name}' (program:{instance}) is in 'loading' state "
                    f"- code is being loaded onto the controller"
                )

            if state == "halted":
                reason = prog_info.get("reasonForHalt", "unknown")
                security_concerns.append(
                    f"HALTED: '{name}' (program:{instance}) is halted "
                    f"(reason: {reason}) - control logic may be inactive"
                )

            if prog_info.get("programChange") and prog_info["programChange"] != "ready":
                security_concerns.append(
                    f"PENDING CHANGE: '{name}' (program:{instance}) has programChange="
                    f"'{prog_info['programChange']}' - a state transition is pending"
                )

            if prog_info.get("programLocation"):
                security_concerns.append(
                    f"LOCATION EXPOSED: '{name}' (program:{instance}) programLocation="
                    f"'{prog_info['programLocation']}' - reveals control logic file path"
                )

        # ===================================================================
        # Step 3: Display results
        # ===================================================================
        # Categorise by state
        running = [p for p in programs if p.get("programState") == "running"]
        halted = [p for p in programs if p.get("programState") == "halted"]
        idle = [p for p in programs if p.get("programState") == "idle"]
        loading = [p for p in programs if p.get("programState") == "loading"]
        other = [
            p
            for p in programs
            if p.get("programState") not in ("running", "halted", "idle", "loading")
        ]

        if running:
            self.logger.success(f"\n  Running programs ({len(running)}):")
            for prog in running:
                name = prog.get("objectName", "?")
                inst_of = prog.get("instanceOf")
                desc = prog.get("description")
                line = f"    program:{prog['instance']} '{name}'"
                if inst_of:
                    line += f" [instanceOf: {inst_of}]"
                if desc:
                    line += f" - {desc}"
                self.logger.display(line)

        if idle:
            self.logger.display(f"\n  Idle programs ({len(idle)}):")
            for prog in idle:
                name = prog.get("objectName", "?")
                self.logger.display(f"    program:{prog['instance']} '{name}'")

        if halted:
            self.logger.warning(f"\n  Halted programs ({len(halted)}):")
            for prog in halted:
                name = prog.get("objectName", "?")
                reason = prog.get("reasonForHalt", "unknown")
                desc_halt = prog.get("descriptionOfHalt")
                line = f"    program:{prog['instance']} '{name}' (reason: {reason})"
                if desc_halt:
                    line += f" - {desc_halt}"
                self.logger.display(line)

        if loading:
            self.logger.warning(f"\n  Loading programs ({len(loading)}):")
            for prog in loading:
                name = prog.get("objectName", "?")
                loc = prog.get("programLocation")
                line = f"    program:{prog['instance']} '{name}'"
                if loc:
                    line += f" [location: {loc}]"
                self.logger.display(line)

        if other:
            self.logger.display(f"\n  Other state programs ({len(other)}):")
            for prog in other:
                name = prog.get("objectName", "?")
                state = prog.get("programState", "?")
                self.logger.display(f"    program:{prog['instance']} '{name}' (state: {state})")

        # Detailed properties for each program
        self.logger.display("\n  Program details:")
        for prog in programs:
            name = prog.get("objectName", "?")
            self.logger.display(f"\n    program:{prog['instance']} '{name}'")
            for key in (
                "programState",
                "programChange",
                "reasonForHalt",
                "descriptionOfHalt",
                "programLocation",
                "instanceOf",
                "description",
            ):
                val = prog.get(key)
                if val is not None:
                    display_key = key[0].upper() + key[1:]
                    # Insert spaces before capitals for readability
                    display_key = "".join(
                        [" " + c if c.isupper() and i > 0 else c for i, c in enumerate(display_key)]
                    ).strip()
                    self.logger.display(f"      {display_key}: {val}")

        # Security concerns
        if security_concerns:
            self.logger.security_finding(
                "Insecure configuration",
                category=Category.ACCESS_CONTROL,
                detail=f"{len(security_concerns)} program security concern(s)",
            )
            for concern in security_concerns:
                self.logger.display(f"      {concern}")

            # programChange is a control property. Its presence/readability is a
            # recon signal but does NOT prove write access (that needs a
            # --confirm write probe), so report it as an exposed control point
            # rather than falsely claiming "Writable access" from a read.
            exposed_count = sum(1 for p in programs if p.get("programChange") is not None)
            if exposed_count > 0:
                self.logger.security_finding(
                    "Program control exposed",
                    category=Category.ACCESS_CONTROL,
                    detail=f"{exposed_count} program object(s) expose a readable programChange property; "
                    "if write access is unauthenticated this would allow unauthorized "
                    "RUN/HALT/RESTART state transitions",
                )
        else:
            self.logger.display("\n  No security concerns identified")

        # Summary
        self.logger.success(
            f"\n  Program enum complete: {len(programs)} program(s) - "
            f"{len(running)} running, {len(idle)} idle, "
            f"{len(halted)} halted, {len(loading)} loading"
        )
