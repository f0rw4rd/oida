"""
BACnet Security Mixin

Handles authentication checks, brute force, DCC, reinit,
BACnet/SC, write testing, writable enumeration, and OOS checks.
"""

import asyncio
from typing import List, Optional

from ..constants import (
    _load_bacpypes3,
    CONTROL_POINT_TYPES,
    BACNET_PRIORITY_LEVELS,
)


class _UnraisableSentinel(BaseException):
    """Placeholder exception that is never raised.

    Used in except-tuples when the real bacpypes3 ``ErrorRejectAbortNack`` is
    absent from a (test-mocked) ``_load_bacpypes3()`` dict. Production always
    supplies the real class, so this only affects unit tests whose fake type
    dicts predate that key -- and those tests never raise it.
    """


class SecurityMixin:
    """Mixin providing BACnet security assessment operations."""

    def _iter_device_objects(self, obj_type_filter=None):
        """Yield (device_id, address, obj_type, instances) for each device's objects.

        Args:
            obj_type_filter: Iterable of object type names to include (default: all).
        """
        if not self.objects:
            return
        for device_id, objects_by_type in self.objects.items():
            device_info = self.devices.get(device_id, {})
            address = device_info.get("address", self.host)
            type_iter = obj_type_filter if obj_type_filter else objects_by_type.keys()
            for obj_type in type_iter:
                instances = objects_by_type.get(obj_type, [])
                if instances:
                    yield device_id, address, obj_type, instances

    def _load_dcc_types(self):
        """Load bacpypes3 types needed for DCC and ReinitializeDevice requests."""
        types = _load_bacpypes3()
        return {
            "DeviceCommunicationControlRequest": types["DeviceCommunicationControlRequest"],
            "DeviceCommunicationControlRequestEnableDisable": types[
                "DeviceCommunicationControlRequestEnableDisable"
            ],
            "CharacterString": types["CharacterString"],
            "ErrorPDU": types["ErrorPDU"],
            "Error": types["Error"],
            "AbortPDU": types["AbortPDU"],
            "RejectPDU": types["RejectPDU"],
            # bacpypes3 RAISES Error/Reject/Abort (all ErrorRejectAbortNack
            # subclasses, which derive from BaseException NOT Exception) from
            # app.request() on e.g. a wrong DCC/reinit password. Callers must
            # catch this explicitly or a single wrong password aborts the whole
            # brute-force. Absent from older test-mocked dicts -> sentinel.
            "ErrorRejectAbortNack": types.get("ErrorRejectAbortNack", _UnraisableSentinel),
        }

    def _build_dcc_request(self, types, password, target_addr):
        """Build a DeviceCommunicationControl 'enable' request with optional password."""
        request = types["DeviceCommunicationControlRequest"](
            enableDisable=types["DeviceCommunicationControlRequestEnableDisable"]("enable"),
        )
        if password:
            request.password = types["CharacterString"](password)
        request.pduDestination = target_addr
        return request

    def _is_success_response(self, response, types):
        """Return True only on an explicit positive ACK from the target.

        Previously this returned True on ``response is None`` (UDP timeout),
        which turned every dropped packet on a filtered / noisy network
        into a false-positive security finding (DCC brute-force success,
        ReinitializeDevice accepted, TimeSync accepted, BBMD foreign-device
        registration accepted, OOS-writable). The whole point of a
        confirmed-service ACK is that absence-of-reply is INDETERMINATE,
        not success.

        Caller contract change: a None response must be interpreted as
        "inconclusive" — emit a debug log, do NOT record a security
        finding. See bacnet/mixins/security.py and bacnet/mixins/network.py
        callers — they now branch on three states (success / failure / no-reply).
        """
        if response is None:
            return False
        return not isinstance(
            response,
            (types["ErrorPDU"], types["Error"], types["AbortPDU"], types["RejectPDU"]),
        )

    def _handle_security_assessment(self):
        """Full security assessment"""
        # The "assessment" calls _handle_test_write (writes back the value it
        # just read — still a real BACnet WriteProperty), _handle_enumerate_writable
        # (writes to every discovered property), and ReinitializeDevice / OOS
        # probes. All are mutating; require --confirm.
        if not self.require_confirm(
            "--assess",
            detail="--assess issues real BACnet WriteProperty + ReinitializeDevice "
            "probes (anonymous-write check, OOS check) — requires --confirm",
        ):
            return
        self.logger.display("\n[Security Assessment]")

        vulns = []

        # Check anonymous read access
        self.logger.display("  Checking anonymous read access...")
        if self.devices:
            self.logger.security_finding(
                "Anonymous access",
                detail="Anonymous read access enabled - no authentication required",
                category="ACCESS_CONTROL",
            )
            vulns.append("Anonymous read access - no authentication required")

        # Check anonymous write access
        self.logger.display("  Checking anonymous write access...")
        self._handle_test_write()

        # Check writable properties
        self.logger.display("  Checking for writable control points...")
        self._handle_enumerate_writable()

        # Check ReinitializeDevice access
        self._handle_check_reinit()

        # Check Out-of-Service capability
        self._handle_check_oos()

        # Report vulnerabilities
        if vulns:
            self.logger.display("\n  [Vulnerabilities Found]")
            for vuln in vulns:
                self.logger.vuln(vuln)

    def _handle_test_write(self):
        """Test write access (non-destructive)

        Despite the docstring this DOES issue a real BACnet WriteProperty —
        it just writes the same value back. Many controllers reject same-
        value writes silently; some log the write. Gated on --confirm to
        prevent accidental SOE pollution.
        """
        if not self.objects:
            return
        if not self.require_confirm(
            "--test-write",
            detail="--test-write issues real BACnet WriteProperty (writes current value back) "
            "— requires --confirm",
        ):
            return
        for device_id, objects_by_type in self.objects.items():
            device_info = self.devices.get(device_id, {})
            address = device_info.get("address", self.host)

            for obj_type in ["analogValue", "binaryValue"]:
                instances = objects_by_type.get(obj_type, [])
                if instances:
                    instance = instances[0]
                    try:
                        current = self._read_property(address, obj_type, instance, "presentValue")
                        if current is None:
                            continue

                        success = self._write_property(
                            address, obj_type, instance, "presentValue", current
                        )
                        if success:
                            self.logger.security_finding(
                                "Writable access",
                                detail=f"Anonymous write access on {obj_type}:{instance}",
                            )
                            return
                    except Exception as e:
                        self.logger.debug(
                            f"Write access test failed for {obj_type}:{instance}: {e}"
                        )

        self.logger.display("  Write access test: No writable objects found")

    def _handle_enumerate_writable(self):
        """Find all writable properties"""
        if not self.objects:
            return
        if not self.require_confirm(
            "--enumerate-writable",
            detail="--enumerate-writable issues a WriteProperty against every discovered "
            "object (pollutes SOE / change-of-value log) — requires --confirm",
        ):
            return
        writable_count = 0

        for _dev_id, address, obj_type, instances in self._iter_device_objects(CONTROL_POINT_TYPES):
            for instance in instances[:5]:
                try:
                    current = self._read_property(address, obj_type, instance, "presentValue")
                    if current is not None:
                        success = self._write_property(
                            address, obj_type, instance, "presentValue", current
                        )
                        if success:
                            writable_count += 1
                except Exception as e:
                    self.logger.debug(f"Writable check failed for {obj_type}:{instance}: {e}")

        if writable_count > 0:
            self.logger.security_finding(
                "Writable access",
                detail=f"Found {writable_count} writable control points",
            )

    def _handle_check_reinit(self):
        """Check if ReinitializeDevice is accessible.

        Reads protocolServicesSupported from each discovered device to determine
        whether the ReinitializeDevice service is advertised. If supported, this
        is a security finding because an unauthenticated attacker may be able to
        reboot or reset the device.
        """
        if not self.devices:
            self.logger.display("  Checking ReinitializeDevice access...")
            self.logger.display("  No devices discovered, skipping ReinitializeDevice check")
            return

        self.logger.display("  Checking ReinitializeDevice access...")

        for device_id, device_info in self.devices.items():
            address = device_info.get("address", self.host)

            # Step 1: Check if the device advertises ReinitializeDevice in its
            # protocolServicesSupported bitstring.
            try:
                services = self._read_property(
                    address, "device", device_id, "protocolServicesSupported"
                )
            except Exception as e:
                self.logger.debug(f"ReinitializeDevice check failed for device {device_id}: {e}")
                services = None

            if services is None:
                self.logger.display(
                    f"  Device {device_id}: Could not read protocolServicesSupported"
                )
                continue

            # protocolServicesSupported is a BACnet bitstring; BAC0 returns it
            # as a list of service names or a bitstring representation.
            services_str = str(services).lower()
            reinit_supported = (
                "reinitializedevice" in services_str or "reinitialize" in services_str
            )

            if reinit_supported:
                self.logger.warning(
                    f"  VULN: Device {device_id} advertises ReinitializeDevice service"
                )
                self.logger.warning("  [!] An attacker may be able to reboot/reset this device")
                self.logger.display(
                    "  Use --test-reinit-pass --confirm to test password protection"
                )
            else:
                self.logger.display(
                    f"  Device {device_id}: ReinitializeDevice not advertised in services"
                )

    def _handle_check_oos(self):
        """Check if Out-of-Service flag can be set"""
        if not self.objects:
            return

        for _dev_id, address, obj_type, instances in self._iter_device_objects(CONTROL_POINT_TYPES):
            for instance in instances[:3]:
                try:
                    oos = self._read_property(address, obj_type, instance, "outOfService")
                    if oos is not None:
                        self.logger.warning(
                            f"  Out-of-Service readable on {obj_type}:{instance}: {oos}"
                        )
                        return
                except Exception as e:
                    self.logger.debug(f"Out-of-Service check failed for {obj_type}:{instance}: {e}")

    def _get_password_list(self) -> List[str]:
        """Get password list for brute force testing"""
        password_file = getattr(self.args, "password_list", None)
        if password_file:
            try:
                with open(password_file) as f:
                    passwords = [line.strip() for line in f if line.strip()]
                self.logger.display(f"  Loaded {len(passwords)} passwords from {password_file}")
                return passwords
            except Exception as e:
                self.logger.warning(f"  Could not load password file: {e}")

        single_pass = getattr(self.args, "password", None)
        if single_pass:
            return [single_pass]

        # Default BACnet common passwords
        return [
            "",  # Empty/no password (most common!)
            "0",
            "1",
            "1234",
            "12345",
            "123456",
            "password",
            "Password",
            "PASSWORD",
            "admin",
            "Admin",
            "ADMIN",
            "bacnet",
            "BACnet",
            "BACNET",
            "default",
            "Default",
            "DEFAULT",
            "system",
            "System",
            "SYSTEM",
            "user",
            "User",
            "USER",
            "guest",
            "Guest",
            "pass",
            "Pass",
            "test",
            "Test",
            "0000",
            "1111",
            "9999",
            "abc123",
            "qwerty",
            "letmein",
            "welcome",
            "changeme",
            "building",
            "hvac",
            "HVAC",
            "bms",
            "BMS",
            "control",
            "Control",
            # Vendor-specific defaults
            "tridium",
            "Tridium",
            "jace",
            "JACE",
            "niagara",
            "Niagara",
            "honeywell",
            "Honeywell",
            "johnson",
            "Johnson",
            "siemens",
            "Siemens",
            "delta",
            "Delta",
            "schneider",
            "Schneider",
            "alerton",
            "Alerton",
            # Documented stack/library defaults. "filister" is the bacnet-stack
            # (bacserv / Steve Karg reference stack) default DCC + Reinitialize
            # password — extremely common on demo gear and devices built on it.
            "filister",
            "Filister",
            "FILISTER",
        ]

    async def _bacpypes3_check_auth(self, app, target_addr, device_id: int, timeout: float):
        """Check authentication requirements"""
        types = _load_bacpypes3()
        ReadPropertyRequest = types["ReadPropertyRequest"]
        ObjectIdentifier = types["ObjectIdentifier"]
        PropertyIdentifier = types["PropertyIdentifier"]
        AbortPDU = types["AbortPDU"]
        ErrorPDU = types["ErrorPDU"]
        RejectPDU = types["RejectPDU"]
        Error = types["Error"]

        self.logger.display("\n[Authentication Check]")

        findings = []

        # Test 1: Anonymous read access
        self.logger.display("  Testing anonymous read access...")
        obj_id = ObjectIdentifier(("device", device_id))
        request = ReadPropertyRequest(
            objectIdentifier=obj_id,
            propertyIdentifier=PropertyIdentifier("objectName"),
        )
        request.pduDestination = target_addr

        try:
            response = await asyncio.wait_for(app.request(request), timeout=timeout)
            if response and not isinstance(response, (AbortPDU, ErrorPDU, RejectPDU, Error)):
                self.logger.security_finding(
                    "Anonymous access",
                    detail="Anonymous READ access allowed",
                    category="ACCESS_CONTROL",
                )
                findings.append("Anonymous read access enabled - no authentication required")
            else:
                self.logger.success("  [+] Anonymous READ access: DENIED")
        except Exception as e:
            self.logger.debug(f"bacpypes3 check auth failed: {e}")
            self.logger.success("  [+] Anonymous READ access: DENIED or filtered")

        # Test 2: Check for password property
        self.logger.display("  Checking for password/authentication properties...")
        auth_props = ["password", "activationPassword", "configurationPassword"]
        for prop in auth_props:
            try:
                request = ReadPropertyRequest(
                    objectIdentifier=obj_id,
                    propertyIdentifier=PropertyIdentifier(prop),
                )
                request.pduDestination = target_addr
                response = await asyncio.wait_for(app.request(request), timeout=2.0)
                if response and not isinstance(response, (AbortPDU, ErrorPDU, RejectPDU, Error)):
                    self.logger.security_finding(
                        "Insecure configuration",
                        detail=f"Password property '{prop}' is readable",
                    )
                    findings.append(f"Password property '{prop}' is readable")
            except Exception as e:
                self.logger.debug(f"bacpypes3 check auth failed: {e}")
                pass

        # Test 3: Check BACnet/SC (Secure Connect) support
        self.logger.display("  Checking BACnet/SC (Secure Connect) support...")
        try:
            request = ReadPropertyRequest(
                objectIdentifier=obj_id,
                propertyIdentifier=PropertyIdentifier("scPrimaryHubUri"),
            )
            request.pduDestination = target_addr
            response = await asyncio.wait_for(app.request(request), timeout=2.0)
            if response and not isinstance(response, (AbortPDU, ErrorPDU, RejectPDU, Error)):
                self.logger.success("  [+] BACnet/SC may be supported")
            else:
                self.logger.display("  [-] No BACnet/SC support detected")
                findings.append("No BACnet/SC (encrypted) support - traffic is cleartext")
        except Exception as e:
            self.logger.debug(f"bacpypes3 check auth failed: {e}")
            self.logger.display("  [-] No BACnet/SC support detected")
            findings.append("No BACnet/SC (encrypted) support - traffic is cleartext")

        # Summary
        if findings:
            self.logger.display("\n  [Security Findings]")
            for finding in findings:
                self.logger.warning(f"    - {finding}")
        else:
            self.logger.success("  No obvious authentication weaknesses found")

    async def _bacpypes3_brute_force_dcc(
        self, app, target_addr, device_id: int, timeout: float
    ) -> Optional[str]:
        """Brute-force the DeviceCommunicationControl password.

        Returns the found password (``""`` for an empty/no-password hit) or None.
        """
        types = self._load_dcc_types()
        passwords = self._get_password_list()

        self.logger.display("\n[Brute Force: DeviceCommunicationControl]")
        self.logger.warning("  WARNING: a correct password lets an attacker mute the device!")
        self.logger.display(f"  Testing {len(passwords)} passwords...")

        for i, password in enumerate(passwords):
            if getattr(self.logger, "verbose", False):
                self.logger.display(
                    f"    [{i + 1}/{len(passwords)}] trying DCC password '{password or '(empty)'}'"
                )
            elif i > 0 and i % 10 == 0:
                self.logger.display(f"    Progress: {i}/{len(passwords)} tested...")
            try:
                request = self._build_dcc_request(types, password, target_addr)
                try:
                    response = await asyncio.wait_for(
                        app.request(request), timeout=min(timeout, 2.0)
                    )
                except (asyncio.TimeoutError, TimeoutError, types["ErrorRejectAbortNack"]) as e:
                    # A wrong password raises Error(...): security: password-failure
                    # (an ErrorRejectAbortNack / BaseException). That is the
                    # EXPECTED result for a non-matching password -- treat it as a
                    # miss and try the next, never let it abort the brute-force.
                    self.logger.debug(f"bacpypes3 dcc brute force failed: {e}")
                    continue
                except Exception as e:
                    self.logger.debug(f"bacpypes3 dcc brute force failed: {e}")
                    continue
                if self._is_success_response(response, types):
                    display_pass = password if password else "(empty)"
                    self.logger.security_finding(
                        "Weak password",
                        detail=f"DCC Password found: '{display_pass}'",
                    )
                    self.logger.success(f"  [Result] DeviceCommunicationControl: '{display_pass}'")
                    return password
            except Exception as e:
                self.logger.debug(f"bacpypes3 dcc brute force failed: {e}")
                continue

        self.logger.display("  [Result] DeviceCommunicationControl: no password found")
        return None

    async def _bacpypes3_brute_force_reinit(
        self, app, target_addr, device_id: int, timeout: float
    ) -> Optional[str]:
        """Brute-force the ReinitializeDevice password.

        ReinitializeDevice uses a SEPARATE password from DCC. Wrong passwords are
        rejected with a security error (no effect); a hit warm-starts the device
        once, then we stop. Returns the found password or None.
        """
        types = self._load_dcc_types()  # error PDU types for _is_success_response
        passwords = self._get_password_list()
        full_types = _load_bacpypes3()
        ReinitializeDeviceRequest = full_types["ReinitializeDeviceRequest"]
        RS = full_types["ReinitializeDeviceRequestReinitializedStateOfDevice"]
        CharacterString = full_types["CharacterString"]

        self.logger.display("\n[Brute Force: ReinitializeDevice]")
        self.logger.warning("  WARNING: a correct password will warm-start (reboot) the device!")
        self.logger.display(f"  Testing {len(passwords)} passwords...")

        for i, password in enumerate(passwords):
            if getattr(self.logger, "verbose", False):
                self.logger.display(
                    f"    [{i + 1}/{len(passwords)}] trying reinit password '{password or '(empty)'}'"
                )
            elif i > 0 and i % 10 == 0:
                self.logger.display(f"    Progress: {i}/{len(passwords)} tested...")
            try:
                request = ReinitializeDeviceRequest(reinitializedStateOfDevice=RS("warmstart"))
                if password:
                    request.password = CharacterString(password)
                request.pduDestination = target_addr
                try:
                    response = await asyncio.wait_for(
                        app.request(request), timeout=min(timeout, 2.0)
                    )
                except (asyncio.TimeoutError, TimeoutError, types["ErrorRejectAbortNack"]) as e:
                    # A wrong password raises Error(...): security: password-failure
                    # (an ErrorRejectAbortNack / BaseException) -- the expected
                    # miss result. Treat it as a miss and continue rather than
                    # letting it abort the brute-force at the first wrong password.
                    self.logger.debug(f"bacpypes3 reinit brute force failed: {e}")
                    continue
                except Exception as e:
                    self.logger.debug(f"bacpypes3 reinit brute force failed: {e}")
                    continue
                if self._is_success_response(response, types):
                    display_pass = password if password else "(empty)"
                    self.logger.security_finding(
                        "Weak password",
                        detail=f"ReinitializeDevice password found: '{display_pass}' - device can be reset",
                    )
                    self.logger.success(f"  [Result] ReinitializeDevice: '{display_pass}'")
                    return password
            except Exception as e:
                self.logger.debug(f"bacpypes3 reinit brute force failed: {e}")
                continue

        self.logger.display("  [Result] ReinitializeDevice: no password found")
        return None

    async def _bacpypes3_brute_force(self, app, target_addr, device_id: int, timeout: float):
        """Run all password brute-force attacks (--brute-force convenience).

        Targeted flags (--brute-force-dcc / --brute-force-reinit) drive the
        per-service methods directly; this just runs both.
        """
        await self._bacpypes3_brute_force_dcc(app, target_addr, device_id, timeout)
        await self._bacpypes3_brute_force_reinit(app, target_addr, device_id, timeout)

    async def _bacpypes3_test_dcc(self, app, target_addr, device_id: int, timeout: float):
        """Test DeviceCommunicationControl access"""
        types = self._load_dcc_types()

        self.logger.display("\n[DeviceCommunicationControl Test]")
        self.logger.warning("  WARNING: This sends actual DCC requests!")

        passwords = self._get_password_list()[:10]

        for password in passwords:
            try:
                request = self._build_dcc_request(types, password, target_addr)

                try:
                    response = await asyncio.wait_for(
                        app.request(request), timeout=min(timeout, 3.0)
                    )

                    if self._is_success_response(response, types):
                        display_pass = password if password else "(empty)"
                        self.logger.security_finding(
                            "Weak password",
                            detail=f"DCC accepted with password: '{display_pass}' - device can be disabled",
                        )
                        return
                    else:
                        response_str = str(response).lower()
                        if "password" in response_str:
                            self.logger.display(f"  [-] Password rejected: '{password}'")
                        elif "service" in response_str and "not" in response_str:
                            self.logger.display("  [-] DCC service not supported")
                            return

                except asyncio.TimeoutError as e:
                    self.logger.debug(f"bacpypes3 test dcc failed: {e}")
                    continue
                except Exception as e:
                    self.logger.debug(f"bacpypes3 test dcc failed: {e}")
                    continue

            except Exception as e:
                self.logger.debug(f"bacpypes3 test dcc failed: {e}")
                continue

        self.logger.display("  No working password found")

    async def _bacpypes3_test_reinit(self, app, target_addr, device_id: int, timeout: float):
        """Test ReinitializeDevice password (DANGEROUS - requires --confirm)"""
        types = _load_bacpypes3()
        ReinitializeDeviceRequest = types["ReinitializeDeviceRequest"]
        ReinitializeDeviceRequestReinitializedStateOfDevice = types[
            "ReinitializeDeviceRequestReinitializedStateOfDevice"
        ]
        CharacterString = types["CharacterString"]
        # Reuse the error-type dict expected by _is_success_response
        err_types = self._load_dcc_types()

        self.logger.display("\n[ReinitializeDevice Password Test]")
        self.logger.warning("  WARNING: This could reset/reboot the device!")
        self.logger.warning("  Using 'warmstart' which is least disruptive")

        passwords = self._get_password_list()[:5]

        for password in passwords:
            try:
                request = ReinitializeDeviceRequest(
                    reinitializedStateOfDevice=ReinitializeDeviceRequestReinitializedStateOfDevice(
                        "warmstart"
                    ),
                )
                if password:
                    request.password = CharacterString(password)
                request.pduDestination = target_addr

                try:
                    response = await asyncio.wait_for(
                        app.request(request), timeout=min(timeout, 3.0)
                    )

                    if self._is_success_response(response, err_types):
                        display_pass = password if password else "(empty)"
                        self.logger.success(f"  [+] ReinitializeDevice accepted: '{display_pass}'")
                        self.logger.warning(
                            "  [!] CRITICAL: Device can be reset with this password!"
                        )
                        return
                    else:
                        response_str = str(response).lower()
                        if "password" in response_str:
                            self.logger.display(f"  [-] Password rejected: '{password}'")

                except asyncio.TimeoutError as e:
                    self.logger.debug(f"bacpypes3 test reinit failed: {e}")
                    continue
                except Exception as e:
                    self.logger.debug(f"bacpypes3 test reinit failed: {e}")
                    continue

            except Exception as e:
                self.logger.debug(f"bacpypes3 test reinit failed: {e}")
                continue

        self.logger.display("  No working password found for ReinitializeDevice")

    async def _bacpypes3_check_bacnet_sc(self, app, target_addr, device_id: int, timeout: float):
        """Check for BACnet Secure Connect (TLS) support"""
        types = _load_bacpypes3()
        ReadPropertyRequest = types["ReadPropertyRequest"]
        ObjectIdentifier = types["ObjectIdentifier"]
        PropertyIdentifier = types["PropertyIdentifier"]
        CharacterString = types["CharacterString"]
        Unsigned = types["Unsigned"]
        AbortPDU = types["AbortPDU"]
        ErrorPDU = types["ErrorPDU"]
        RejectPDU = types["RejectPDU"]
        Error = types["Error"]

        self.logger.display("\n[BACnet/SC (Secure Connect) Check]")

        obj_id = ObjectIdentifier(("device", device_id))

        sc_properties = [
            ("scPrimaryHubUri", "SC Primary Hub URI"),
            ("scFailoverHubUri", "SC Failover Hub URI"),
            ("scMinimumReconnectTime", "SC Minimum Reconnect Time"),
            ("scMaximumReconnectTime", "SC Maximum Reconnect Time"),
            ("scConnectWaitTimeout", "SC Connect Wait Timeout"),
            ("scDisconnectWaitTimeout", "SC Disconnect Wait Timeout"),
            ("scHeartbeatTimeout", "SC Heartbeat Timeout"),
            ("scHubConnectorState", "SC Hub Connector State"),
        ]

        sc_found = False
        findings = []

        for prop_name, display_name in sc_properties:
            try:
                request = ReadPropertyRequest(
                    objectIdentifier=obj_id,
                    propertyIdentifier=PropertyIdentifier(prop_name),
                )
                request.pduDestination = target_addr

                try:
                    response = await asyncio.wait_for(
                        app.request(request), timeout=min(timeout, 2.0)
                    )
                    if response and not isinstance(
                        response, (AbortPDU, ErrorPDU, RejectPDU, Error)
                    ):
                        sc_found = True
                        value = "present"
                        pv = getattr(response, "propertyValue", None)
                        if pv is not None and hasattr(pv, "cast_out"):
                            for cast_type in (CharacterString, Unsigned):
                                try:
                                    decoded = pv.cast_out(cast_type)
                                    if decoded is not None:
                                        value = decoded
                                        break
                                except Exception as e:
                                    self.logger.debug(f"BACnet/SC property decode failed: {e}")
                                    continue
                        findings.append(f"{display_name}: {value}")
                except asyncio.TimeoutError as e:
                    self.logger.debug(f"bacpypes3 check bacnet sc failed: {e}")
                    continue
            except Exception as e:
                self.logger.debug(f"bacpypes3 check bacnet sc failed: {e}")
                continue

        if sc_found:
            self.logger.success("  [+] BACnet/SC (Secure Connect) SUPPORTED")
            self.logger.display("  Device supports TLS-encrypted BACnet communication")
            for finding in findings:
                self.logger.display(f"      {finding}")
        else:
            self.logger.display("  [-] No BACnet/SC support detected")
            self.logger.security_finding(
                "No encryption",
                detail="All BACnet/IP traffic is unencrypted - implement BACnet/SC or network segmentation",
                category="ENCRYPTION",
            )

    async def _bacpypes3_test_priority_writes(
        self, app, target_addr, device_id: int, timeout: float
    ):
        """Test write access at all 16 BACnet priority levels.

        BACnet uses a priority array (1-16) for commandable objects.
        Priority 1 (Life Safety) is highest. This tests which levels
        accept writes, revealing if critical priorities are unprotected.
        """
        types = _load_bacpypes3()
        WritePropertyRequest = types["WritePropertyRequest"]
        ObjectIdentifier = types["ObjectIdentifier"]
        PropertyIdentifier = types["PropertyIdentifier"]
        Real = types["Real"]
        Unsigned = types["Unsigned"]
        BinaryPV = types["BinaryPV"]
        AbortPDU = types["AbortPDU"]
        ErrorPDU = types["ErrorPDU"]
        RejectPDU = types["RejectPDU"]
        Error = types["Error"]
        AnyAtomic = types["AnyAtomic"]

        self.logger.display("\n[Priority Write Test - All 16 Levels]")
        self.logger.warning("  WARNING: This tests write access at each priority level")
        self.logger.display("  Writes back the current value, then relinquishes (writes Null to)")
        self.logger.display("  each priority slot that accepted the write")

        # Find a commandable object to test
        test_obj = None
        for obj_type in ["analogOutput", "analogValue", "binaryOutput", "binaryValue"]:
            if device_id in self.objects and obj_type in self.objects[device_id]:
                instances = self.objects[device_id][obj_type]
                if instances:
                    test_obj = (obj_type, instances[0])
                    break

        if not test_obj:
            self.logger.display("  No commandable objects found to test")
            return

        obj_type, instance = test_obj
        obj_id = ObjectIdentifier((obj_type, instance))
        self.logger.display(f"  Testing on {obj_type}:{instance}")

        # presentValue datatype is object-type dependent: Real for analog*,
        # BinaryPV enumeration for binary*. Decoding and re-encoding with the
        # wrong type makes a spec-compliant device reject every write with a
        # datatype error, masking a real writable-priority weakness.
        is_binary = obj_type in ("binaryOutput", "binaryValue")
        cast_types = (BinaryPV, Unsigned) if is_binary else (Real,)

        # Read current value first
        ReadPropertyRequest_ = types["ReadPropertyRequest"]
        try:
            request = ReadPropertyRequest_(
                objectIdentifier=obj_id,
                propertyIdentifier=PropertyIdentifier("presentValue"),
            )
            request.pduDestination = target_addr
            response = await asyncio.wait_for(app.request(request), timeout=timeout)
            current_value = None
            if response and not isinstance(response, (AbortPDU, ErrorPDU, RejectPDU, Error)):
                pv = getattr(response, "propertyValue", None)
                if pv is not None and hasattr(pv, "cast_out"):
                    for cast_type in cast_types:
                        try:
                            current_value = pv.cast_out(cast_type)
                            if current_value is not None:
                                break
                        except Exception as e:
                            self.logger.debug(f"bacpypes3 test priority writes failed: {e}")
                            continue
        except Exception as e:
            self.logger.debug(f"bacpypes3 test priority writes failed: {e}")
            current_value = None

        if current_value is None:
            self.logger.warning("  Could not read current value, skipping write test")
            return

        self.logger.display(f"  Current value: {current_value}")

        # Encode the write value with the object's actual datatype so the
        # write-back is non-destructive AND type-valid for this object.
        if is_binary:
            try:
                write_value = BinaryPV(current_value)
            except Exception as e:
                self.logger.debug(f"could not encode BinaryPV for write-back: {e}")
                self.logger.warning(
                    "  Could not encode current value as BinaryPV, skipping write test"
                )
                return
        else:
            write_value = Real(current_value)

        from bacpypes3.primitivedata import Null

        writable_priorities = []
        unrelinquished = []

        for priority in range(1, 17):
            priority_name = BACNET_PRIORITY_LEVELS.get(priority, f"Priority {priority}")

            try:
                request = WritePropertyRequest(
                    objectIdentifier=obj_id,
                    propertyIdentifier=PropertyIdentifier("presentValue"),
                    propertyValue=AnyAtomic(write_value),
                    priority=Unsigned(priority),
                )
                request.pduDestination = target_addr

                try:
                    response = await asyncio.wait_for(
                        app.request(request), timeout=min(timeout, 3.0)
                    )

                    err_types = {
                        "ErrorPDU": ErrorPDU,
                        "Error": Error,
                        "AbortPDU": AbortPDU,
                        "RejectPDU": RejectPDU,
                    }
                    if self._is_success_response(response, err_types):
                        writable_priorities.append(priority)
                        self.logger.warning(
                            f"    [!] Priority {priority:2d} ({priority_name}): WRITABLE"
                        )
                        # Relinquish immediately: writing Null clears this
                        # priority slot so the probe doesn't leave the
                        # (possibly Life Safety) priority occupied.
                        try:
                            relinquish_request = WritePropertyRequest(
                                objectIdentifier=obj_id,
                                propertyIdentifier=PropertyIdentifier("presentValue"),
                                propertyValue=AnyAtomic(Null()),
                                priority=Unsigned(priority),
                            )
                            relinquish_request.pduDestination = target_addr
                            relinquish_response = await asyncio.wait_for(
                                app.request(relinquish_request), timeout=min(timeout, 3.0)
                            )
                            if not self._is_success_response(relinquish_response, err_types):
                                unrelinquished.append(priority)
                                self.logger.warning(
                                    f"    [!] Priority {priority:2d}: relinquish rejected — "
                                    "priority slot left occupied"
                                )
                        except (asyncio.TimeoutError, TimeoutError) as e:
                            unrelinquished.append(priority)
                            self.logger.debug(f"relinquish priority {priority} timed out: {e}")
                            self.logger.warning(
                                f"    [!] Priority {priority:2d}: relinquish timed out — "
                                "priority slot may be left occupied"
                            )
                        except Exception as e:
                            unrelinquished.append(priority)
                            self.logger.debug(f"relinquish priority {priority} failed: {e}")
                            self.logger.warning(
                                f"    [!] Priority {priority:2d}: relinquish failed ({e}) — "
                                "priority slot may be left occupied"
                            )
                    else:
                        self.logger.display(
                            f"    [-] Priority {priority:2d} ({priority_name}): rejected"
                        )
                except (asyncio.TimeoutError, TimeoutError) as e:
                    self.logger.debug(f"bacpypes3 test priority writes failed: {e}")
                    self.logger.display(
                        f"    [?] Priority {priority:2d} ({priority_name}): timeout"
                    )
                except Exception as e:
                    self.logger.debug(f"bacpypes3 test priority writes failed: {e}")

            except Exception as e:
                self.logger.debug(f"Priority {priority} write error: {e}")

        # Summary
        self.logger.display("\n  [Priority Write Summary]")
        if writable_priorities:
            self.logger.warning(
                f"  [!] {len(writable_priorities)} priority level(s) writable: {writable_priorities}"
            )
            critical = [p for p in writable_priorities if p <= 2]
            if critical:
                self.logger.security_finding(
                    "Writable access",
                    detail=f"Life Safety priorities writable: {critical} - attacker can override life safety controls",
                )
            operator = [p for p in writable_priorities if p == 8]
            if operator:
                self.logger.warning(
                    "  [!] HIGH: Operator priority (8) writable - can override automation"
                )
            if unrelinquished:
                self.logger.warning(
                    f"  [!] Could not relinquish {len(unrelinquished)} priority level(s): "
                    f"{unrelinquished} — manually verify/clear on the device"
                )
            else:
                self.logger.display("  All writable priorities were relinquished (Null write-back)")
        else:
            self.logger.display("  No priority levels accepted writes (device may reject all)")

    async def _read_device_local_time(self, app, target_addr, device_id: int, timeout: float):
        """Read the device object's localDate + localTime, returning a (date, time) pair.

        Returns ``(date_value, time_value)`` on success, or ``None`` if either
        property could not be read. Used to verify TimeSynchronization
        out-of-band, since the service itself is unconfirmed and never ACKs.
        """
        types = _load_bacpypes3()
        ReadPropertyRequest = types["ReadPropertyRequest"]
        ObjectIdentifier = types["ObjectIdentifier"]
        PropertyIdentifier = types["PropertyIdentifier"]
        AbortPDU = types["AbortPDU"]
        ErrorPDU = types["ErrorPDU"]
        RejectPDU = types["RejectPDU"]
        Error = types["Error"]
        err_types = (AbortPDU, ErrorPDU, RejectPDU, Error)

        dev_id = ObjectIdentifier(("device", device_id))
        values = []
        for prop in ("localDate", "localTime"):
            try:
                request = ReadPropertyRequest(
                    objectIdentifier=dev_id,
                    propertyIdentifier=PropertyIdentifier(prop),
                )
                request.pduDestination = target_addr
                response = await asyncio.wait_for(app.request(request), timeout=min(timeout, 3.0))
            except Exception as e:
                self.logger.debug(f"read {prop} for time-sync verification failed: {e}")
                return None
            if response is None or isinstance(response, err_types):
                return None
            values.append(getattr(response, "propertyValue", None))
        return (values[0], values[1])

    async def _bacpypes3_test_time_sync(self, app, target_addr, device_id: int, timeout: float):
        """Test if device accepts unauthenticated time synchronization.

        TimeSynchronization is an UNCONFIRMED BACnet service: a compliant
        device never sends an application-layer reply, so absence-of-reply
        proves nothing about whether the write was applied. We therefore do
        NOT treat ``response is None`` (or a timeout) as a finding. Instead we
        verify out-of-band: read the device's localDate/localTime before and
        after sending a deliberately skewed time, and only report a finding if
        the clock actually moved.
        """
        types = _load_bacpypes3()
        TimeSynchronizationRequest = types["TimeSynchronizationRequest"]
        DateTime = types["DateTime"]
        Date = types["Date"]
        Time = types["Time"]

        self.logger.display("\n[Time Synchronization Test]")
        self.logger.warning("  WARNING: This sends actual time sync requests!")

        from datetime import datetime, timedelta

        # Read the clock before, so we can detect an actual change.
        before = await self._read_device_local_time(app, target_addr, device_id, timeout)

        # Send a deliberately skewed time so a successful write is observable
        # against the device's real clock when we re-read.
        skewed = datetime.now() + timedelta(minutes=5)
        self.logger.display("  Sending TimeSynchronization with a skewed time (+5 min)...")

        try:
            # TimeSynchronizationRequest has a single 'time' element of type
            # DateTime (date + time), not separate date=/time= kwargs.
            request = TimeSynchronizationRequest(
                time=DateTime(
                    date=Date((skewed.year - 1900, skewed.month, skewed.day, skewed.weekday() + 1)),
                    time=Time((skewed.hour, skewed.minute, skewed.second, 0)),
                ),
            )
            request.pduDestination = target_addr

            try:
                await asyncio.wait_for(app.request(request), timeout=min(timeout, 3.0))
            except (asyncio.TimeoutError, TimeoutError):
                # Expected for an unconfirmed service — NOT evidence of anything.
                pass
        except Exception as e:
            self.logger.debug(f"Time sync test error: {e}")
            self.logger.display(f"  Time sync test failed: {e}")
            return

        # Verify out-of-band. Absence of an ACK is meaningless for an
        # unconfirmed service, so we compare the clock before vs after.
        after = await self._read_device_local_time(app, target_addr, device_id, timeout)

        if before is None or after is None:
            self.logger.display(
                "  [?] Sent TimeSynchronization; result indeterminate "
                "(unconfirmed service, could not read localDate/localTime to verify)"
            )
            return

        if str(before) != str(after):
            self.logger.security_finding(
                "Unauthenticated time synchronization",
                detail=(
                    "Device applied an unauthenticated TimeSynchronization "
                    f"(localDate/localTime changed {before} -> {after}) - attacker can "
                    "desynchronize clocks, corrupting trend logs and schedule timing"
                ),
            )
            # The write was accepted, so the device is now +5min fast. Restore
            # the correct time -- an intrusive probe must not leave the target
            # clock permanently skewed (the exact harm the finding warns about).
            now = datetime.now()
            try:
                restore = TimeSynchronizationRequest(
                    time=DateTime(
                        date=Date((now.year - 1900, now.month, now.day, now.weekday() + 1)),
                        time=Time((now.hour, now.minute, now.second, 0)),
                    ),
                )
                restore.pduDestination = target_addr
                try:
                    await asyncio.wait_for(app.request(restore), timeout=min(timeout, 3.0))
                except (asyncio.TimeoutError, TimeoutError):
                    pass  # unconfirmed service -- no ACK expected
                self.logger.display("  Restored device clock to the correct time")
            except Exception as e:
                self.logger.debug(f"Time sync restore failed: {e}")
                self.logger.display(
                    "  [!] Could not restore device clock -- it may remain +5 min fast"
                )
        else:
            self.logger.success(
                "  [+] Device clock unchanged after TimeSynchronization (write not applied)"
            )

    async def _bacpypes3_test_oos(self, app, target_addr, device_id: int, timeout: float):
        """Test if Out-of-Service flag can be set on control objects.

        Setting outOfService=True disconnects a BACnet object from its
        physical I/O, effectively disabling that control loop. This tests
        if the flag can be written without authentication.
        """
        types = _load_bacpypes3()
        ReadPropertyRequest = types["ReadPropertyRequest"]
        WritePropertyRequest = types["WritePropertyRequest"]
        ObjectIdentifier = types["ObjectIdentifier"]
        PropertyIdentifier = types["PropertyIdentifier"]
        AbortPDU = types["AbortPDU"]
        ErrorPDU = types["ErrorPDU"]
        RejectPDU = types["RejectPDU"]
        Error = types["Error"]

        self.logger.display("\n[Out-of-Service Flag Test]")
        self.logger.display("  Testing if outOfService can be read/written on control objects")

        test_objects = []
        for obj_type in ["analogOutput", "binaryOutput", "analogInput", "binaryInput"]:
            if device_id in self.objects and obj_type in self.objects[device_id]:
                for inst in self.objects[device_id][obj_type][:2]:
                    test_objects.append((obj_type, inst))

        if not test_objects:
            self.logger.display("  No control I/O objects found to test")
            return

        readable = []
        writable = []

        for obj_type, instance in test_objects:
            obj_id = ObjectIdentifier((obj_type, instance))

            # Reset per object: oos_value must reflect THIS object's read. Without
            # this, an object whose read fails (error PDU / no reply) would inherit
            # a prior object's stale value and — with --confirm — get that wrong
            # value written to it (or UnboundLocalError on the first object).
            oos_value: object = "unknown"

            # Test read
            try:
                request = ReadPropertyRequest(
                    objectIdentifier=obj_id,
                    propertyIdentifier=PropertyIdentifier("outOfService"),
                )
                request.pduDestination = target_addr

                response = await asyncio.wait_for(app.request(request), timeout=min(timeout, 3.0))

                if response and not isinstance(response, (AbortPDU, ErrorPDU, RejectPDU, Error)):
                    from bacpypes3.primitivedata import Boolean

                    oos_value = "unknown"
                    pv = getattr(response, "propertyValue", None)
                    if pv is not None and hasattr(pv, "cast_out"):
                        try:
                            oos_value = bool(pv.cast_out(Boolean))
                        except Exception as e:
                            self.logger.debug(f"bacpypes3 test oos failed: {e}")
                    readable.append((obj_type, instance, oos_value))
                    self.logger.display(
                        f"  {obj_type}:{instance} outOfService={oos_value} (readable)"
                    )
            except (asyncio.TimeoutError, TimeoutError) as e:
                self.logger.debug(f"bacpypes3 test oos failed: {e}")
                continue
            except Exception as e:
                self.logger.debug(f"bacpypes3 test oos failed: {e}")
                continue

            # Test write (write current value back - non-destructive)
            if not self._confirm_flag():
                continue

            try:
                from bacpypes3.primitivedata import Boolean

                # Write the CURRENT value back, not a hardcoded False: forcing an
                # object that was legitimately Out-Of-Service (maintenance) back
                # into service reconnects physical I/O -- a real state change, not
                # the "non-destructive" probe the old code claimed. Skip when the
                # current value couldn't be read.
                if not isinstance(oos_value, bool):
                    self.logger.debug(
                        f"  {obj_type}:{instance} outOfService unreadable -- skipping write test"
                    )
                    continue

                request = WritePropertyRequest(
                    objectIdentifier=obj_id,
                    propertyIdentifier=PropertyIdentifier("outOfService"),
                )
                from bacpypes3.constructeddata import AnyAtomic

                request.propertyValue = AnyAtomic(Boolean(oos_value))
                request.pduDestination = target_addr

                response = await asyncio.wait_for(app.request(request), timeout=min(timeout, 3.0))

                # A no-reply (None) is INDETERMINATE, not a successful write —
                # route through the shared contract so a dropped/filtered packet
                # does not become a false "outOfService is writable" finding.
                if self._is_success_response(response, types):
                    writable.append((obj_type, instance))
                    self.logger.security_finding(
                        "Writable access",
                        detail=f"{obj_type}:{instance} outOfService is writable",
                    )
            except (asyncio.TimeoutError, TimeoutError) as e:
                self.logger.debug(f"bacpypes3 test oos failed: {e}")
                continue
            except Exception as e:
                self.logger.debug(f"bacpypes3 test oos failed: {e}")
                continue

        # Summary
        self.logger.display("\n  [Out-of-Service Summary]")
        self.logger.display(f"  Readable: {len(readable)} objects")
        if writable:
            self.logger.security_finding(
                "Writable access",
                detail=f"{len(writable)} objects have writable outOfService flag - control loops can be disabled",
            )
        elif not self._confirm_flag() and readable:
            self.logger.display("  Write test skipped (use --confirm to test writes)")
