"""
BACnet Discovery Mixin

Handles device discovery via Who-Is, direct reads, and device identification.
"""

import asyncio
from typing import Any, Dict, List, NamedTuple, Optional

from ..constants import (
    _load_bacpypes3,
    VENDORS,
    CONTROL_POINT_TYPES,
)


class Bacpypes3CommonTypes(NamedTuple):
    """The bacpypes3 types shared by the vendor scan and present-value read paths."""

    ReadPropertyRequest: Any
    ObjectIdentifier: Any
    PropertyIdentifier: Any
    CharacterString: Any
    Unsigned: Any
    Real: Any
    AbortPDU: Any
    ErrorPDU: Any
    RejectPDU: Any
    Error: Any
    ErrorRejectAbortNack: Any


def _unpack_bacpypes3_common_types(types: Dict[str, Any]) -> Bacpypes3CommonTypes:
    """Unpack the ``_load_bacpypes3()`` types shared by the vendor-scan and
    present-value-read paths (ReadPropertyRequest/ObjectIdentifier/PropertyIdentifier
    plus the standard abort/error/reject exception types)."""
    return Bacpypes3CommonTypes(
        ReadPropertyRequest=types["ReadPropertyRequest"],
        ObjectIdentifier=types["ObjectIdentifier"],
        PropertyIdentifier=types["PropertyIdentifier"],
        CharacterString=types["CharacterString"],
        Unsigned=types["Unsigned"],
        Real=types["Real"],
        AbortPDU=types["AbortPDU"],
        ErrorPDU=types["ErrorPDU"],
        RejectPDU=types["RejectPDU"],
        Error=types["Error"],
        ErrorRejectAbortNack=types["ErrorRejectAbortNack"],
    )


class DiscoveryMixin:
    """Mixin providing BACnet device discovery operations."""

    async def _async_handle_who_is(self):
        """Broadcast Who-Is discovery request (async)"""
        self.logger.display("Broadcasting Who-Is discovery...")

        try:
            # Parse device range if specified
            low_limit = None
            high_limit = None
            device_range = getattr(self.args, "device_range", None)
            if device_range:
                if "-" in device_range:
                    low_limit, high_limit = map(int, device_range.split("-"))
                else:
                    low_limit = high_limit = int(device_range)

            # Send Who-Is (method is who_is in BAC0, and it's async)
            timeout = getattr(self.args, "timeout", 3.0)
            await self.bacnet.who_is(low_limit=low_limit, high_limit=high_limit)

            # Wait for responses (async)
            await asyncio.sleep(timeout)

            # Collect discovered devices
            if hasattr(self.bacnet, "discoveredDevices") and self.bacnet.discoveredDevices:
                for device in self.bacnet.discoveredDevices:
                    device_id = device[0] if isinstance(device, tuple) else device
                    address = device[1] if isinstance(device, tuple) and len(device) > 1 else None

                    self.devices[device_id] = {
                        "device_id": device_id,
                        "address": str(address) if address else self.host,
                    }
                    self.logger.success(f"Found device: {device_id} at {address or self.host}")

            if not self.devices:
                # Try alternative method
                self._discover_via_read()

            if self.devices:
                self.logger.display(f"Discovered {len(self.devices)} device(s)")
            else:
                self.logger.warning("No devices discovered")

        except Exception as e:
            self.logger.debug(f"async handle who is failed: {e}")
            self.logger.fail(f"Who-Is discovery failed: {e}")

    def _discover_via_read(self):
        """Try to discover device by direct read"""
        try:
            # Try to read device object from target
            device_id = getattr(self.args, "device_id", None)
            if device_id:
                self.devices[device_id] = {
                    "device_id": device_id,
                    "address": self.host,
                }
                self.logger.success(f"Using specified device ID: {device_id}")
        except Exception as e:
            self.logger.debug(f"Device ID parsing failed: {e}")

    def _handle_identify(self):
        """Read device identification for discovered devices"""
        if not self.devices:
            self.logger.warning("No devices to identify. Run --who-is first.")
            return

        for device_id, device_info in self.devices.items():
            self.logger.display(f"\n[Device {device_id}]")
            try:
                address = device_info.get("address", self.host)

                # Read device properties
                properties = [
                    ("objectName", "Name"),
                    ("vendorIdentifier", "Vendor ID"),
                    ("vendorName", "Vendor"),
                    ("modelName", "Model"),
                    ("firmwareRevision", "Firmware"),
                    ("applicationSoftwareVersion", "App Version"),
                    ("serialNumber", "Serial"),
                    ("description", "Description"),
                    ("location", "Location"),
                    ("protocolVersion", "Protocol Version"),
                    ("protocolRevision", "Protocol Revision"),
                    ("maxApduLengthAccepted", "Max APDU"),
                    ("segmentationSupported", "Segmentation"),
                ]

                for prop_name, display_name in properties:
                    try:
                        value = self._read_property(address, "device", device_id, prop_name)
                        if value is not None:
                            # Resolve vendor name if we got vendor ID
                            if prop_name == "vendorIdentifier":
                                vendor_name = VENDORS.get(value, f"Unknown ({value})")
                                device_info["vendor_id"] = value
                                device_info["vendor_name"] = vendor_name
                                self.logger.success(f"  {display_name}: {value} ({vendor_name})")
                            elif prop_name == "vendorName" and value:
                                device_info["vendor_name"] = str(value)
                                self.logger.display(f"  {display_name}: {value}")
                            else:
                                device_info[prop_name] = value
                                self.logger.display(f"  {display_name}: {value}")
                    except Exception as e:
                        self.logger.debug(f"Property read failed for {prop_name}: {e}")

            except Exception as e:
                self.logger.debug(f"handle identify failed: {e}")
                self.logger.fail(f"Failed to identify device {device_id}: {e}")

    async def _bacpypes3_who_is_instance(self, app, target_addr, timeout: float) -> Optional[int]:
        """Send a directed Who-Is to the target and return the I-Am instance.

        Returns the lowest instance reported (a single host normally answers with
        one I-Am) or None if no device answered / Who-Is is unsupported.
        """
        try:
            # Cap the wait: who_is resolves only after its own internal timeout
            # elapses, so a long --timeout would otherwise stall the probe here.
            who_is_timeout = max(1.0, min(3.0, timeout))
            iams = await asyncio.wait_for(
                app.who_is(address=target_addr, timeout=who_is_timeout),
                timeout=who_is_timeout + 1.0,
            )
        except (asyncio.TimeoutError, TimeoutError) as e:
            self.logger.debug(f"bacpypes3 directed Who-Is timed out: {e}")
            return None
        except Exception as e:
            self.logger.debug(f"bacpypes3 directed Who-Is failed: {e}")
            return None

        instances = []
        for iam in iams or []:
            try:
                ident = iam.iAmDeviceIdentifier
                # ObjectIdentifier behaves like a ('device', instance) 2-tuple.
                instance = ident[1] if not isinstance(ident, int) else ident
                instances.append(int(instance))
            except Exception as e:
                self.logger.debug(f"bacpypes3 I-Am parse failed: {e}")
                continue

        if instances:
            # A directed I-Am came back: a real BACnet device answered.
            self._bacnet_response_seen = True
            return min(instances)
        return None

    async def _bacpypes3_discover_device(self, app, target_addr, timeout: float) -> Optional[int]:
        """Discover the device instance.

        A BACnet device instance is a 22-bit value (0..4194302), so brute-probing
        a handful of common IDs misses any real device that did not happen to pick
        one of them. The protocol-correct way is a directed Who-Is: the device
        answers with an I-Am that carries its actual instance. We try that first
        (one round trip, works for any instance) and only fall back to the
        common-ID ReadProperty probe for stacks that ignore unicast Who-Is.
        """
        types = _load_bacpypes3()
        ReadPropertyRequest = types["ReadPropertyRequest"]
        ObjectIdentifier = types["ObjectIdentifier"]
        PropertyIdentifier = types["PropertyIdentifier"]
        AbortPDU = types["AbortPDU"]
        ErrorPDU = types["ErrorPDU"]
        RejectPDU = types["RejectPDU"]
        Error = types["Error"]

        instance = await self._bacpypes3_who_is_instance(app, target_addr, timeout)
        if instance is not None:
            self.logger.success(f"Discovered device ID: {instance} (via Who-Is)")
            return instance

        common_ids = [1, 10, 100, 1000, 10000, 100000, 1234, 12345]

        # The probe walks several candidate device IDs serially. On a dead /
        # firewalled host every probe times out, so without an overall budget
        # the loop would run len(common_ids) * per_probe seconds and blow past
        # the user-supplied --timeout. Bound the whole sequence to ~timeout and
        # size each probe so the budget is shared across the candidates.
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        per_probe = max(0.5, min(2.0, timeout / len(common_ids)))

        for test_id in common_ids:
            if loop.time() >= deadline:
                self.logger.debug("bacpypes3 discover device: timeout budget exhausted")
                break
            try:
                request = ReadPropertyRequest(
                    objectIdentifier=ObjectIdentifier(("device", test_id)),
                    propertyIdentifier=PropertyIdentifier("objectName"),
                )
                request.pduDestination = target_addr

                remaining = deadline - loop.time()
                if remaining <= 0:
                    break
                try:
                    response = await asyncio.wait_for(
                        app.request(request), timeout=min(per_probe, remaining)
                    )
                except (asyncio.TimeoutError, TimeoutError) as e:
                    self.logger.debug(f"bacpypes3 discover device failed: {e}")
                    continue
                except Exception as e:
                    self.logger.debug(f"bacpypes3 discover device failed: {e}")
                    continue

                if response and not isinstance(response, (AbortPDU, ErrorPDU, RejectPDU, Error)):
                    self._bacnet_response_seen = True
                    self.logger.success(f"Discovered device ID: {test_id}")
                    return test_id
            except Exception as e:
                self.logger.debug(f"bacpypes3 discover device failed: {e}")
                continue

        return None

    async def _bacpypes3_read_properties(
        self, app, target_addr, device_id: int, timeout: float
    ) -> Dict[str, Any]:
        """Read device properties using bacpypes3"""
        types = _load_bacpypes3()
        ReadPropertyRequest = types["ReadPropertyRequest"]
        ObjectIdentifier = types["ObjectIdentifier"]
        PropertyIdentifier = types["PropertyIdentifier"]
        CharacterString = types["CharacterString"]
        Unsigned = types["Unsigned"]
        Segmentation = types["Segmentation"]
        AbortPDU = types["AbortPDU"]
        ErrorPDU = types["ErrorPDU"]
        RejectPDU = types["RejectPDU"]

        # Property name, result key, expected type
        properties_to_read = [
            ("objectName", "object_name", CharacterString),
            ("vendorName", "vendor_name", CharacterString),
            ("vendorIdentifier", "vendor_id", Unsigned),
            ("modelName", "model_name", CharacterString),
            ("firmwareRevision", "firmware_revision", CharacterString),
            (
                "applicationSoftwareVersion",
                "application_software_version",
                CharacterString,
            ),
            ("description", "description", CharacterString),
            ("location", "location", CharacterString),
            ("protocolVersion", "protocol_version", Unsigned),
            ("protocolRevision", "protocol_revision", Unsigned),
            ("maxApduLengthAccepted", "max_apdu_length", Unsigned),
            ("segmentationSupported", "segmentation", Segmentation),
        ]

        results = {}
        obj_id = ObjectIdentifier(("device", device_id))

        for prop_name, result_key, expected_type in properties_to_read:
            try:
                request = ReadPropertyRequest(
                    objectIdentifier=obj_id,
                    propertyIdentifier=PropertyIdentifier(prop_name),
                )
                request.pduDestination = target_addr

                try:
                    response = await asyncio.wait_for(app.request(request), timeout=timeout)
                except (asyncio.TimeoutError, TimeoutError) as e:
                    self.logger.debug(f"bacpypes3 read properties failed: {e}")
                    continue
                except Exception as e:
                    self.logger.debug(f"bacpypes3 read properties failed: {e}")
                    continue

                if response and not isinstance(response, (AbortPDU, ErrorPDU, RejectPDU)):
                    self._bacnet_response_seen = True
                    if hasattr(response, "propertyValue"):
                        pv = response.propertyValue
                        if hasattr(pv, "cast_out"):
                            try:
                                value = pv.cast_out(expected_type)
                                results[result_key] = str(value) if value is not None else ""

                                # Resolve vendor ID to name (only if device didn't report vendorName)
                                if result_key == "vendor_id" and not results.get("vendor_name"):
                                    try:
                                        vid = int(value)
                                        results["vendor_name"] = VENDORS.get(
                                            vid, f"Unknown ({vid})"
                                        )
                                    except (ValueError, TypeError) as e:
                                        self.logger.debug(f"bacpypes3 read properties failed: {e}")
                            except Exception as e:
                                self.logger.debug(f"bacpypes3 read properties failed: {e}")
                                try:
                                    value = pv.cast_out(CharacterString)
                                    results[result_key] = str(value) if value else ""
                                except Exception as e:
                                    self.logger.debug(f"bacpypes3 read properties failed: {e}")
            except Exception as e:
                self.logger.debug(f"bacpypes3 read properties failed: {e}")
                continue

        return results

    async def _bacpypes3_vendor_scan(self, app, target_addr, device_id: int, timeout: float):
        """Scan for proprietary/vendor-specific object types and properties.

        BACnet reserves object types 128-1023 and property IDs 512+ for
        vendor-proprietary extensions. These can reveal undocumented features,
        debug interfaces, passwords, or configuration backdoors.
        """
        types = _load_bacpypes3()
        (
            ReadPropertyRequest,
            ObjectIdentifier,
            PropertyIdentifier,
            CharacterString,
            Unsigned,
            Real,
            AbortPDU,
            ErrorPDU,
            RejectPDU,
            Error,
            ErrorRejectAbortNack,
        ) = _unpack_bacpypes3_common_types(types)

        self.logger.display("\n[Vendor-Specific / Proprietary Scan]")

        # --- Step 1: Identify the vendor from the device object ---
        vendor_id = None
        vendor_name = "Unknown"
        device_obj_id = ObjectIdentifier(("device", device_id))

        try:
            request = ReadPropertyRequest(
                objectIdentifier=device_obj_id,
                propertyIdentifier=PropertyIdentifier("vendorIdentifier"),
            )
            request.pduDestination = target_addr

            try:
                response = await asyncio.wait_for(app.request(request), timeout=min(timeout, 3.0))
                if response and not isinstance(response, (AbortPDU, ErrorPDU, RejectPDU, Error)):
                    self._bacnet_response_seen = True
                    pv = getattr(response, "propertyValue", None)
                    if pv is not None and hasattr(pv, "cast_out"):
                        try:
                            vendor_id = int(pv.cast_out(Unsigned))
                            vendor_name = VENDORS.get(vendor_id, f"Unknown ({vendor_id})")
                        except Exception as e:
                            self.logger.debug(f"bacpypes3 vendor scan failed: {e}")
            except (asyncio.TimeoutError, TimeoutError) as e:
                self.logger.debug(f"bacpypes3 vendor scan failed: {e}")
            except Exception as e:
                self.logger.debug(f"bacpypes3 vendor scan failed: {e}")
        except Exception as e:
            self.logger.debug(f"bacpypes3 vendor scan failed: {e}")

        self.logger.display(f"  Vendor: {vendor_name} (ID: {vendor_id})")

        # Known vendor patterns for proprietary objects/properties. Vendor IDs
        # are the official ASHRAE assigned-vendor-ids (bacnet.org), matching the
        # VENDORS map; the proprietary-property probe range (512+) is the generic
        # BACnet vendor-proprietary band, not vendor-specific intelligence.
        known_vendor_patterns = {
            36: {  # Tridium / Niagara
                "name": "Tridium/Niagara",
                "suspect_props": [512, 513, 514, 515, 516, 517, 518, 519, 520],
                "notes": "Niagara Framework - check for NiagaraStation config props",
            },
            7: {  # Siemens Schweiz AG
                "name": "Siemens",
                "suspect_props": [512, 513, 514, 515, 520, 521, 522, 530, 540],
                "notes": "Siemens Desigo/PXC - may expose engineering access props",
            },
            17: {  # Honeywell
                "name": "Honeywell",
                "suspect_props": [512, 513, 514, 515, 516, 524, 525, 530, 540, 550],
                "notes": "Honeywell WEBs/Spyder - check for service tool properties",
            },
            18: {  # Alerton / Honeywell
                "name": "Alerton/Honeywell",
                "suspect_props": [512, 513, 514, 515, 516, 524, 525, 530, 540, 550],
                "notes": "Alerton/Honeywell - check for service tool properties",
            },
            5: {  # Johnson Controls
                "name": "Johnson Controls",
                "suspect_props": [512, 513, 514, 515, 516, 517, 518, 530, 540],
                "notes": "JCI Metasys - may have NAE/NCE debug properties",
            },
            10: {  # Schneider Electric
                "name": "Schneider Electric",
                "suspect_props": [512, 513, 514, 515, 520, 525, 530],
                "notes": "Schneider SmartStruxure - check for engineering props",
            },
        }

        vendor_info = known_vendor_patterns.get(vendor_id, None)
        if vendor_info:
            self.logger.display(f"  Known vendor pattern: {vendor_info['name']}")
            self.logger.display(f"  Note: {vendor_info['notes']}")

        # --- Step 2: Probe proprietary object types 128-170 ---
        self.logger.display("\n  [Proprietary Object Type Scan (128-170)]")
        proprietary_objects = []

        for obj_type_num in range(128, 171):
            for instance in range(1, 6):
                try:
                    # BACnet proprietary object types are referenced by their numeric ID
                    # bacpypes3 ObjectIdentifier accepts (type_int, instance)
                    obj_id = ObjectIdentifier((obj_type_num, instance))

                    request = ReadPropertyRequest(
                        objectIdentifier=obj_id,
                        propertyIdentifier=PropertyIdentifier("objectName"),
                    )
                    request.pduDestination = target_addr

                    try:
                        response = await asyncio.wait_for(
                            app.request(request), timeout=min(timeout, 2.0)
                        )
                    except (asyncio.TimeoutError, TimeoutError) as e:
                        self.logger.debug(f"bacpypes3 vendor scan failed: {e}")
                        continue
                    except (Exception, ErrorRejectAbortNack) as e:
                        self.logger.debug(f"bacpypes3 vendor scan failed: {e}")
                        continue

                    if response and not isinstance(
                        response, (AbortPDU, ErrorPDU, RejectPDU, Error)
                    ):
                        obj_name = f"type{obj_type_num}:{instance}"
                        pv = getattr(response, "propertyValue", None)
                        if pv is not None and hasattr(pv, "cast_out"):
                            try:
                                decoded = pv.cast_out(CharacterString)
                                if decoded:
                                    obj_name = str(decoded).strip()
                            except Exception as e:
                                self.logger.debug(f"bacpypes3 vendor scan failed: {e}")

                        proprietary_objects.append(
                            {
                                "type_num": obj_type_num,
                                "instance": instance,
                                "name": obj_name,
                            }
                        )
                        self.logger.display(
                            f"    [+] Proprietary object type {obj_type_num}, "
                            f"instance {instance}: '{obj_name}'"
                        )

                except Exception as e:
                    self.logger.debug(f"bacpypes3 vendor scan failed: {e}")
                    continue

        if not proprietary_objects:
            self.logger.display("    No proprietary object types found in range 128-170")

        # --- Step 3: Probe proprietary properties on device and control objects ---
        self.logger.display("\n  [Proprietary Property Scan (IDs 512-560)]")

        # Collect target objects: device object + control point objects
        target_objects: List[tuple] = [("device", device_id)]

        if device_id in self.objects:
            for obj_type in CONTROL_POINT_TYPES:
                if obj_type in self.objects[device_id]:
                    for inst in self.objects[device_id][obj_type][:2]:
                        target_objects.append((obj_type, inst))

        # Also include any proprietary objects we just discovered
        for prop_obj in proprietary_objects[:5]:
            target_objects.append((prop_obj["type_num"], prop_obj["instance"]))

        # Limit total objects to scan
        target_objects = target_objects[:15]

        # Determine property IDs to probe
        prop_ids_to_scan = list(range(512, 561))
        if vendor_info and "suspect_props" in vendor_info:
            # Prioritize known suspect properties for this vendor
            suspect = vendor_info["suspect_props"]
            # Put suspect props first, then fill in remaining
            remaining = [p for p in prop_ids_to_scan if p not in suspect]
            prop_ids_to_scan = suspect + remaining

        proprietary_properties = []
        suspicious_findings = []

        # Patterns that suggest sensitive content
        sensitive_patterns = [
            "password",
            "passwd",
            "pwd",
            "secret",
            "key",
            "token",
            "auth",
            "login",
            "credential",
            "debug",
            "diag",
            "test",
            "admin",
            "root",
            "config",
            "backdoor",
            "override",
            "bypass",
            "enable",
            "unlock",
            "service",
            "engineer",
            "factory",
            "maintenance",
            "hidden",
            "internal",
            "private",
        ]

        for obj_type, obj_instance in target_objects:
            obj_id = ObjectIdentifier((obj_type, obj_instance))
            obj_label = f"{obj_type}:{obj_instance}"
            found_for_object = 0

            for prop_id in prop_ids_to_scan:
                try:
                    request = ReadPropertyRequest(
                        objectIdentifier=obj_id,
                        propertyIdentifier=PropertyIdentifier(prop_id),
                    )
                    request.pduDestination = target_addr

                    try:
                        response = await asyncio.wait_for(
                            app.request(request), timeout=min(timeout, 2.0)
                        )
                    except (asyncio.TimeoutError, TimeoutError) as e:
                        self.logger.debug(f"bacpypes3 vendor scan failed: {e}")
                        continue
                    except (Exception, ErrorRejectAbortNack) as e:
                        self.logger.debug(f"bacpypes3 vendor scan failed: {e}")
                        continue

                    if response and not isinstance(
                        response, (AbortPDU, ErrorPDU, RejectPDU, Error)
                    ):
                        # Extract value from response. propertyValue is an
                        # untyped Any for proprietary properties, so try each
                        # plausible primitive via cast_out.
                        raw_value = None
                        display_value = f"(property {prop_id} present)"

                        pv = getattr(response, "propertyValue", None)
                        if pv is not None and hasattr(pv, "cast_out"):
                            for cast_type in (CharacterString, Real, Unsigned):
                                try:
                                    decoded = pv.cast_out(cast_type)
                                except Exception as e:
                                    self.logger.debug(f"bacpypes3 vendor scan failed: {e}")
                                    continue
                                if decoded is None:
                                    continue
                                if cast_type is CharacterString:
                                    str_val = str(decoded).strip()
                                    if not str_val:
                                        continue
                                    display_value = f"'{str_val}'"
                                    raw_value = str_val
                                else:
                                    display_value = str(decoded)
                                    raw_value = str(decoded)
                                break

                        prop_finding = {
                            "object": obj_label,
                            "property_id": prop_id,
                            "value": display_value,
                            "raw": raw_value,
                        }
                        proprietary_properties.append(prop_finding)
                        found_for_object += 1

                        self.logger.display(f"    [+] {obj_label} prop:{prop_id} = {display_value}")

                        # Check for suspicious content
                        if raw_value:
                            raw_lower = str(raw_value).lower()
                            for pattern in sensitive_patterns:
                                if pattern in raw_lower:
                                    suspicious_findings.append(
                                        {
                                            "object": obj_label,
                                            "property_id": prop_id,
                                            "value": display_value,
                                            "pattern": pattern,
                                        }
                                    )
                                    break

                except Exception as e:
                    self.logger.debug(f"bacpypes3 vendor scan failed: {e}")
                    continue

            if found_for_object > 0:
                self.logger.debug(f"  {obj_label}: {found_for_object} proprietary properties found")

        if not proprietary_properties:
            self.logger.display("    No proprietary properties found in range 512-560")

        # --- Step 4: Report vendor-specific findings ---
        self.logger.display("\n  [Vendor-Specific Findings Summary]")
        self.logger.display(f"  Vendor: {vendor_name} (ID: {vendor_id})")
        self.logger.display(f"  Proprietary objects found: {len(proprietary_objects)}")
        self.logger.display(f"  Proprietary properties found: {len(proprietary_properties)}")

        # Known vendor-specific warnings
        if vendor_id == 89:  # Tridium/Niagara
            self.logger.warning(
                "  [!] Tridium/Niagara detected - check for NiagaraStation "
                "web interface on ports 80/443/3011"
            )
            self.logger.warning(
                "  [!] Niagara devices may expose Fox protocol (port 1911) "
                "with additional attack surface"
            )
        elif vendor_id == 7:  # Siemens
            self.logger.warning(
                "  [!] Siemens BT detected - check for ABT Site/Desigo CC engineering access"
            )
        elif vendor_id in (4, 6):  # Honeywell
            self.logger.warning(
                "  [!] Honeywell detected - check for WEBs-AX/N4 web "
                "interface and Niagara sub-components"
            )
        elif vendor_id == 5:  # Johnson Controls
            self.logger.warning(
                "  [!] Johnson Controls detected - check for Metasys "
                "NAE/NCE/OAS interfaces and default credentials"
            )
        elif vendor_id == 222:  # Schneider Electric
            self.logger.warning(
                "  [!] Schneider Electric detected - check for SmartStruxure "
                "Server/Enterprise Server web access"
            )

        # Suspicious findings
        if suspicious_findings:
            self.logger.warning(
                f"\n  [!] CRITICAL: {len(suspicious_findings)} potentially "
                f"sensitive proprietary properties detected:"
            )
            for finding in suspicious_findings:
                self.logger.warning(
                    f"      {finding['object']} prop:{finding['property_id']} "
                    f"= {finding['value']} (matched: '{finding['pattern']}')"
                )
            self.logger.warning(
                "  [!] These properties may contain passwords, keys, debug "
                "interfaces, or configuration backdoors"
            )

        # Undocumented properties summary
        if proprietary_properties:
            undocumented_count = len(proprietary_properties) - len(suspicious_findings)
            if undocumented_count > 0:
                self.logger.display(
                    f"\n  {undocumented_count} undocumented vendor properties "
                    f"respond but content is not flagged as sensitive"
                )
                self.logger.display(
                    "  These may still contain useful information for further analysis"
                )
