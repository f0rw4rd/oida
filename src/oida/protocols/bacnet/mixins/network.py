"""
BACnet Network Mixin

Handles BBMD, FDT, router discovery, and remote network scanning.
"""

import asyncio
from ..constants import _load_bacpypes3


class NetworkMixin:
    """Mixin providing BACnet network reconnaissance operations."""

    async def _bacpypes3_who_has(self, app, target_addr, object_name: str, timeout: float):
        """Search for object by name using Who-Has broadcast"""
        types = _load_bacpypes3()
        WhoHasRequest = types["WhoHasRequest"]
        CharacterString = types["CharacterString"]
        WhoHasObject = types["WhoHasObject"]
        AbortPDU = types["AbortPDU"]
        ErrorPDU = types["ErrorPDU"]
        RejectPDU = types["RejectPDU"]
        Error = types["Error"]

        self.logger.display(f"\n[Who-Has Search: '{object_name}']")

        try:
            # WhoHasRequest carries the search criteria in its 'object' element
            # (a WhoHasObject choice); there is no top-level objectName kwarg.
            request = WhoHasRequest(
                object=WhoHasObject(objectName=CharacterString(object_name)),
            )
            request.pduDestination = target_addr

            try:
                response = await asyncio.wait_for(app.request(request), timeout=timeout)
                if response and not isinstance(response, (AbortPDU, ErrorPDU, RejectPDU, Error)):
                    self.logger.success(f"  Object '{object_name}' found!")
                    if hasattr(response, "deviceIdentifier"):
                        self.logger.display(f"    Device: {response.deviceIdentifier}")
                    if hasattr(response, "objectIdentifier"):
                        self.logger.display(f"    Object: {response.objectIdentifier}")
                else:
                    self.logger.display(f"  Object '{object_name}' not found")
            except asyncio.TimeoutError as e:
                self.logger.debug(f"bacpypes3 who has failed: {e}")
                self.logger.display("  No response (timeout)")
        except Exception as e:
            self.logger.debug(f"Who-Has error: {e}")

    async def _bacpypes3_enum_bbmd(self, app, target_addr, timeout: float):
        """Enumerate BBMD Broadcast Distribution Table"""
        types = _load_bacpypes3()
        ReadBroadcastDistributionTable = types["ReadBroadcastDistributionTable"]

        self.logger.display("\n[BBMD Broadcast Distribution Table]")

        try:
            request = ReadBroadcastDistributionTable()
            request.pduDestination = target_addr

            try:
                response = await asyncio.wait_for(app.request(request), timeout=timeout)
                if response:
                    self.logger.success("  BBMD Table readable!")
                    self.logger.display(f"    Response: {response}")
                else:
                    self.logger.display("  BBMD not enabled or not accessible")
            except asyncio.TimeoutError as e:
                self.logger.debug(f"bacpypes3 enum bbmd failed: {e}")
                self.logger.display("  No BBMD response (timeout)")
        except Exception as e:
            self.logger.debug(f"BBMD enum error: {e}")
            self.logger.display("  BBMD enumeration not available")

    async def _bacpypes3_enum_fdt(self, app, target_addr, timeout: float):
        """Enumerate BBMD Foreign Device Table"""
        types = _load_bacpypes3()
        ReadForeignDeviceTable = types["ReadForeignDeviceTable"]

        self.logger.display("\n[BBMD Foreign Device Table]")

        try:
            request = ReadForeignDeviceTable()
            request.pduDestination = target_addr

            try:
                response = await asyncio.wait_for(app.request(request), timeout=timeout)
                if response:
                    self.logger.success("  Foreign Device Table readable!")
                    self.logger.warning("  [!] FDT access may allow rogue device registration")
                    self.logger.display(f"    Response: {response}")
                else:
                    self.logger.display("  FDT not accessible or BBMD not enabled")
            except asyncio.TimeoutError as e:
                self.logger.debug(f"bacpypes3 enum fdt failed: {e}")
                self.logger.display("  No FDT response (timeout)")
        except Exception as e:
            self.logger.debug(f"FDT enum error: {e}")
            self.logger.display("  FDT enumeration not available")

    async def _bacpypes3_enum_routers(self, app, target_addr, timeout: float):
        """Discover BACnet routers and network topology"""
        types = _load_bacpypes3()
        WhoIsRouterToNetwork = types["WhoIsRouterToNetwork"]

        self.logger.display("\n[BACnet Router Discovery]")

        try:
            request = WhoIsRouterToNetwork()
            request.pduDestination = target_addr

            try:
                response = await asyncio.wait_for(app.request(request), timeout=timeout)
                if response:
                    self.logger.success("  Router(s) found!")
                    self.logger.display(f"    Response: {response}")
                else:
                    self.logger.display("  No routers found or not responding")
            except asyncio.TimeoutError as e:
                self.logger.debug(f"bacpypes3 enum routers failed: {e}")
                self.logger.display("  No router response (timeout)")
        except Exception as e:
            self.logger.debug(f"Router enum error: {e}")
            self.logger.display("  Router discovery not available")

    async def _bacpypes3_discover_networks(self, app, target_addr, timeout: float):
        """Discover remote BACnet networks behind routers"""
        types = _load_bacpypes3()
        ReadPropertyRequest = types["ReadPropertyRequest"]
        ObjectIdentifier = types["ObjectIdentifier"]
        PropertyIdentifier = types["PropertyIdentifier"]
        AbortPDU = types["AbortPDU"]
        ErrorPDU = types["ErrorPDU"]
        RejectPDU = types["RejectPDU"]
        Error = types["Error"]

        self.logger.display("\n[Remote Network Discovery]")
        self.logger.display("  Scanning for BACnet networks behind router...")

        if not hasattr(self, "remote_networks"):
            self.remote_networks = []

        # Probe for network-port objects (type 56). The port count is derived
        # from the objects we actually find — bacpypes3 has no
        # 'numberOfNetworkPorts' PropertyIdentifier to read directly.
        self.logger.display("  Probing for network-port objects...")
        network_ports = []

        for port_instance in range(1, 10):
            try:
                obj_id = ObjectIdentifier(("networkPort", port_instance))

                request = ReadPropertyRequest(
                    objectIdentifier=obj_id,
                    propertyIdentifier=PropertyIdentifier("objectName"),
                )
                request.pduDestination = target_addr

                try:
                    response = await asyncio.wait_for(
                        app.request(request), timeout=min(timeout, 2.0)
                    )
                    if response and not isinstance(
                        response, (AbortPDU, ErrorPDU, RejectPDU, Error)
                    ):
                        port_name = "unknown"
                        if hasattr(response, "propertyValue") and hasattr(
                            response.propertyValue, "tagList"
                        ):
                            tags = list(response.propertyValue.tagList)
                            for tag in tags:
                                if hasattr(tag, "tag_data") and tag.tag_data:
                                    try:
                                        port_name = tag.tag_data.decode(
                                            "utf-8", errors="replace"
                                        ).strip()
                                        break
                                    except Exception as e:
                                        self.logger.debug(f"Port name decode failed: {e}")

                        # Try to read network number for this port
                        net_num = None
                        try:
                            request2 = ReadPropertyRequest(
                                objectIdentifier=obj_id,
                                propertyIdentifier=PropertyIdentifier("networkNumber"),
                            )
                            request2.pduDestination = target_addr
                            response2 = await asyncio.wait_for(
                                app.request(request2), timeout=min(timeout, 2.0)
                            )
                            if response2 and not isinstance(
                                response2, (AbortPDU, ErrorPDU, RejectPDU, Error)
                            ):
                                if hasattr(response2, "propertyValue") and hasattr(
                                    response2.propertyValue, "tagList"
                                ):
                                    tags2 = list(response2.propertyValue.tagList)
                                    for tag in tags2:
                                        if (
                                            hasattr(tag, "tag_data")
                                            and tag.tag_data
                                            and len(tag.tag_data) <= 4
                                        ):
                                            net_num = int.from_bytes(tag.tag_data, "big")
                                            break
                        except Exception as e:
                            self.logger.debug(f"Network number read failed: {e}")

                        # Try to read network type
                        net_type = None
                        try:
                            request3 = ReadPropertyRequest(
                                objectIdentifier=obj_id,
                                propertyIdentifier=PropertyIdentifier("networkType"),
                            )
                            request3.pduDestination = target_addr
                            response3 = await asyncio.wait_for(
                                app.request(request3), timeout=min(timeout, 2.0)
                            )
                            if response3 and not isinstance(
                                response3, (AbortPDU, ErrorPDU, RejectPDU, Error)
                            ):
                                if hasattr(response3, "propertyValue") and hasattr(
                                    response3.propertyValue, "tagList"
                                ):
                                    tags3 = list(response3.propertyValue.tagList)
                                    for tag in tags3:
                                        if hasattr(tag, "tag_data") and tag.tag_data:
                                            type_val = int.from_bytes(tag.tag_data, "big")
                                            net_types = {
                                                0: "Ethernet",
                                                1: "ARCNET",
                                                2: "MS/TP",
                                                3: "PTP",
                                                4: "LonTalk",
                                                5: "BACnet/IP",
                                                6: "ZigBee",
                                                7: "Virtual",
                                                8: "Non-BACnet",
                                                9: "BACnet/SC",
                                            }
                                            net_type = net_types.get(type_val, f"Type-{type_val}")
                                            break
                        except Exception as e:
                            self.logger.debug(f"Network type read failed: {e}")

                        network_ports.append(
                            {
                                "instance": port_instance,
                                "name": port_name,
                                "network": net_num,
                                "type": net_type,
                            }
                        )

                        if net_num is not None and net_num not in self.remote_networks:
                            self.remote_networks.append(net_num)

                except asyncio.TimeoutError as e:
                    self.logger.debug(f"bacpypes3 discover networks failed: {e}")
                    continue
            except Exception as e:
                self.logger.debug(f"bacpypes3 discover networks failed: {e}")
                continue

        if network_ports:
            self.logger.success(f"  Found {len(network_ports)} network port(s):")
            for port in network_ports:
                net_info = f"Network {port['network']}" if port["network"] else "No network"
                type_info = f" ({port['type']})" if port["type"] else ""
                self.logger.display(
                    f"    Port {port['instance']}: {port['name']} - {net_info}{type_info}"
                )

            if self.remote_networks:
                self.logger.display(f"\n  Remote networks discovered: {self.remote_networks}")
                self.logger.display(
                    "  Use --scan-network N to discover devices on remote network N"
                )
                self.logger.display("  Use --scan-all-networks to scan all discovered networks")
        else:
            self.logger.display("  No network-port objects found (device may not be a router)")

    async def _bacpypes3_scan_remote_network(
        self, app, target_addr, network_num: int, timeout: float
    ):
        """Scan a specific remote network for devices"""
        types = _load_bacpypes3()
        WhoIsRequest = types["WhoIsRequest"]
        GlobalBroadcast = types["GlobalBroadcast"]
        AbortPDU = types["AbortPDU"]
        ErrorPDU = types["ErrorPDU"]
        RejectPDU = types["RejectPDU"]
        Error = types["Error"]

        self.logger.display(f"\n[Scanning Remote Network {network_num}]")
        self.logger.display(f"  Sending Who-Is to network {network_num}...")

        try:
            request = WhoIsRequest()

            try:
                request.pduDestination = GlobalBroadcast()
            except Exception as e:
                self.logger.debug(f"Address creation error: {e}")
                request.pduDestination = target_addr

            responses = []
            try:
                response = await asyncio.wait_for(app.request(request), timeout=timeout)
                if response and not isinstance(response, (AbortPDU, ErrorPDU, RejectPDU, Error)):
                    responses.append(response)
            except asyncio.TimeoutError as e:
                self.logger.debug(f"bacpypes3 scan remote network failed: {e}")
                pass
            except Exception as e:
                self.logger.debug(f"Who-Is error: {e}")

            self.logger.display("  Listening for I-Am responses...")
            await asyncio.sleep(2.0)

            if responses:
                self.logger.success(f"  Found {len(responses)} device(s) on network {network_num}")
                for resp in responses:
                    self.logger.display(f"    {resp}")
            else:
                self.logger.display(f"  No devices responded on network {network_num}")
                self.logger.display("  Note: MS/TP devices may be slow to respond")

        except Exception as e:
            self.logger.debug(f"Remote scan error: {e}")
            self.logger.display(f"  Error scanning network {network_num}")

    async def _bacpypes3_scan_all_networks(self, app, target_addr, timeout: float):
        """Scan all discovered remote networks for devices"""
        self.logger.display("\n[Scanning All Remote Networks]")

        if not hasattr(self, "remote_networks") or not self.remote_networks:
            self.logger.display("  Discovering networks first...")
            await self._bacpypes3_discover_networks(app, target_addr, timeout)

        if not self.remote_networks:
            self.logger.display("  No remote networks found to scan")
            return

        self.logger.display(
            f"  Scanning {len(self.remote_networks)} network(s): {self.remote_networks}"
        )

        for net_num in self.remote_networks:
            self.logger.display(f"\n  --- Network {net_num} ---")
            await self._bacpypes3_scan_remote_network(app, target_addr, net_num, timeout)

    async def _bacpypes3_test_bbmd_injection(self, app, target_addr, timeout: float):
        """Test if BBMD accepts foreign device registration or BDT writes.

        A vulnerable BBMD allows attackers to:
        - Register as a foreign device to receive all broadcast traffic
        - Inject entries into the Broadcast Distribution Table
        - Redirect BACnet broadcast traffic through attacker-controlled nodes
        """
        types = _load_bacpypes3()
        RegisterForeignDevice = types["RegisterForeignDevice"]
        WriteBroadcastDistributionTable = types["WriteBroadcastDistributionTable"]
        ReadBroadcastDistributionTable = types["ReadBroadcastDistributionTable"]

        self.logger.display("\n[BBMD Injection Test]")
        self.logger.warning("  WARNING: This sends actual BBMD registration requests!")

        findings = []

        # Test 1: Read current BDT
        self.logger.display("  Reading Broadcast Distribution Table...")
        try:
            request = ReadBroadcastDistributionTable()
            request.pduDestination = target_addr

            try:
                response = await asyncio.wait_for(app.request(request), timeout=timeout)
                if response:
                    self.logger.warning("  [!] BDT readable - BBMD is active")
                    findings.append("BBMD BDT readable without authentication")
                    self.logger.display(f"    BDT entries: {response}")
                else:
                    self.logger.display("  [-] BDT not readable or BBMD not enabled")
            except (asyncio.TimeoutError, TimeoutError) as e:
                self.logger.debug(f"bacpypes3 test bbmd injection failed: {e}")
                self.logger.display("  [-] BDT read timeout")
        except Exception as e:
            self.logger.debug(f"BDT read error: {e}")

        # Test 2: Foreign device registration
        self.logger.display("  Testing foreign device registration...")
        try:
            request = RegisterForeignDevice(ttl=60)
            request.pduDestination = target_addr

            try:
                response = await asyncio.wait_for(app.request(request), timeout=min(timeout, 3.0))

                if response is None:
                    # No reply on UDP is INDETERMINATE — could be silent accept,
                    # could be a filter, could be packet loss. Don't emit a
                    # CRITICAL security_finding on absence of evidence.
                    self.logger.debug(
                        "  Foreign device registration: no reply (inconclusive — "
                        "target may have accepted silently or filtered the BVLL "
                        "Register-Foreign-Device PDU)"
                    )
                elif hasattr(response, "bvlciResultCode"):
                    code = response.bvlciResultCode
                    if code == 0:
                        self.logger.warning(
                            "  [!] CRITICAL: Foreign device registration ACCEPTED (code=0)"
                        )
                        findings.append("Foreign device registration accepted (result=success)")
                    else:
                        self.logger.display(f"  [-] Registration rejected (code={code})")
                else:
                    self.logger.display(f"  [-] Registration response: {response}")

            except (asyncio.TimeoutError, TimeoutError) as e:
                self.logger.debug(f"bacpypes3 test bbmd injection failed: {e}")
                self.logger.display("  [-] Registration timeout (may not be BBMD)")
        except Exception as e:
            self.logger.debug(f"FD registration error: {e}")
            self.logger.display("  [-] Foreign device registration not supported")

        # Test 3: BDT write attempt
        self.logger.display("  Testing BDT write access...")
        try:
            # Send empty BDT write to test if writes are accepted
            request = WriteBroadcastDistributionTable(bdt=[])
            request.pduDestination = target_addr

            try:
                response = await asyncio.wait_for(app.request(request), timeout=min(timeout, 3.0))

                if response is None:
                    # No reply on UDP is INDETERMINATE. Do not emit a
                    # security_finding on absence of evidence.
                    self.logger.debug(
                        "  BBMD BDT write: no reply (inconclusive — could be "
                        "silent accept, filter, or packet loss)"
                    )
                elif hasattr(response, "bvlciResultCode"):
                    code = response.bvlciResultCode
                    if code == 0:
                        self.logger.security_finding(
                            "Writable access",
                            detail="BBMD BDT write accepted (result=success)",
                        )
                        findings.append("BBMD BDT write accepted (result=success)")
                    else:
                        self.logger.display(f"  [-] BDT write rejected (code={code})")
                else:
                    self.logger.display(f"  [-] BDT write response: {response}")

            except (asyncio.TimeoutError, TimeoutError) as e:
                self.logger.debug(f"bacpypes3 test bbmd injection failed: {e}")
                self.logger.display("  [-] BDT write timeout")
        except Exception as e:
            self.logger.debug(f"BDT write error: {e}")
            self.logger.display("  [-] BDT write test not available")

        # Summary
        if findings:
            self.logger.display("\n  [BBMD Injection Summary]")
            for finding in findings:
                self.logger.warning(f"    [!] {finding}")
            self.logger.warning("  [!] BBMD injection allows traffic interception and redirection")
        else:
            self.logger.display("  BBMD injection tests: No vulnerabilities found")

    async def _bacpypes3_discover_mstp(self, app, target_addr, device_id: int, timeout: float):
        """Discover MS/TP devices behind BACnet/IP routers.

        BACnet MS/TP (Master-Slave/Token-Passing) is a serial RS-485 protocol
        commonly used behind BACnet/IP routers. Devices on MS/TP segments are
        often invisible to IP-only scanners. This method discovers them by:
          1. Reading network-port objects to identify MS/TP interfaces
          2. Probing each MS/TP segment for devices via the router
          3. Reading basic identification from discovered remote devices
          4. Reporting topology and flagging security concerns
        """
        types = _load_bacpypes3()
        ReadPropertyRequest = types["ReadPropertyRequest"]
        ObjectIdentifier = types["ObjectIdentifier"]
        PropertyIdentifier = types["PropertyIdentifier"]
        WhoIsRequest = types["WhoIsRequest"]
        AbortPDU = types["AbortPDU"]
        ErrorPDU = types["ErrorPDU"]
        RejectPDU = types["RejectPDU"]
        Error = types["Error"]
        Address = types["Address"]

        error_types = (AbortPDU, ErrorPDU, RejectPDU, Error)

        self.logger.display("\n[MS/TP Device Discovery Behind Routers]")

        # ── Helper: read a single property from a target, return raw tag value ──
        async def _read_prop(obj_id, prop_name, dest_addr, req_timeout=None):
            """Read a single property and return the raw tag data or None."""
            if req_timeout is None:
                req_timeout = min(timeout, 3.0)
            try:
                request = ReadPropertyRequest(
                    objectIdentifier=obj_id,
                    propertyIdentifier=PropertyIdentifier(prop_name),
                )
                request.pduDestination = dest_addr
                response = await asyncio.wait_for(app.request(request), timeout=req_timeout)
                if response and not isinstance(response, error_types):
                    if hasattr(response, "propertyValue") and hasattr(
                        response.propertyValue, "tagList"
                    ):
                        return list(response.propertyValue.tagList)
                return None
            except asyncio.TimeoutError as e:
                self.logger.debug(f"read prop failed: {e}")
                return None
            except Exception as e:
                self.logger.debug(f"  Read {prop_name} from {obj_id} failed: {e}")
                return None

        async def _read_uint(obj_id, prop_name, dest_addr, req_timeout=None):
            """Read a property and interpret the first tag as an unsigned integer."""
            tags = await _read_prop(obj_id, prop_name, dest_addr, req_timeout)
            if tags:
                for tag in tags:
                    if hasattr(tag, "tag_data") and tag.tag_data and len(tag.tag_data) <= 4:
                        return int.from_bytes(tag.tag_data, "big")
            return None

        async def _read_string(obj_id, prop_name, dest_addr, req_timeout=None):
            """Read a property and interpret the first tag as a UTF-8 string."""
            tags = await _read_prop(obj_id, prop_name, dest_addr, req_timeout)
            if tags:
                for tag in tags:
                    if hasattr(tag, "tag_data") and tag.tag_data:
                        try:
                            return tag.tag_data.decode("utf-8", errors="replace").strip()
                        except Exception as e:
                            self.logger.debug(f"read string failed: {e}")
                            pass
            return None

        async def _read_bool(obj_id, prop_name, dest_addr, req_timeout=None):
            """Read a property and interpret the first tag as a boolean."""
            tags = await _read_prop(obj_id, prop_name, dest_addr, req_timeout)
            if tags:
                for tag in tags:
                    if hasattr(tag, "tag_data") and tag.tag_data:
                        return int.from_bytes(tag.tag_data, "big") != 0
            return None

        async def _read_bytes(obj_id, prop_name, dest_addr, req_timeout=None):
            """Read a property and return raw bytes from the first tag."""
            tags = await _read_prop(obj_id, prop_name, dest_addr, req_timeout)
            if tags:
                for tag in tags:
                    if hasattr(tag, "tag_data") and tag.tag_data:
                        return bytes(tag.tag_data)
            return None

        # ── Network type name mapping ──
        net_type_names = {
            0: "Ethernet",
            1: "ARCNET",
            2: "MS/TP",
            3: "PTP",
            4: "LonTalk",
            5: "BACnet/IP",
            6: "ZigBee",
            7: "Virtual",
            8: "Non-BACnet",
            9: "BACnet/SC",
        }

        # ══════════════════════════════════════════════════════════════════════
        # Phase 1: Router Detection and Network Topology
        # ══════════════════════════════════════════════════════════════════════
        self.logger.display("  Phase 1: Reading router network port configuration...")

        network_ports = []  # list of dicts with port metadata
        mstp_ports = []  # subset that are MS/TP type
        security_findings = []

        # bacpypes3 has no 'numberOfNetworkPorts' PropertyIdentifier, so probe
        # a fixed window of network-port object instances (type 56) directly.
        self.logger.display("    Probing network-port object instances...")
        max_probe = 10
        for port_instance in range(1, max_probe + 1):
            port_obj_id = ObjectIdentifier(("networkPort", port_instance))

            # Read objectName to confirm the port exists
            port_name = await _read_string(port_obj_id, "objectName", target_addr)
            if port_name is None:
                continue

            # Read networkType
            net_type_val = await _read_uint(port_obj_id, "networkType", target_addr)
            net_type_str = (
                net_type_names.get(net_type_val, f"Type-{net_type_val}")
                if net_type_val is not None
                else "unknown"
            )

            # Read networkNumber
            net_number = await _read_uint(port_obj_id, "networkNumber", target_addr)

            # Read macAddress
            mac_raw = await _read_bytes(port_obj_id, "macAddress", target_addr)
            mac_display = None
            if mac_raw:
                if len(mac_raw) == 1:
                    mac_display = str(mac_raw[0])
                elif len(mac_raw) == 6:
                    mac_display = ":".join(f"{b:02x}" for b in mac_raw)
                else:
                    mac_display = mac_raw.hex()

            port_info = {
                "instance": port_instance,
                "name": port_name,
                "networkType": net_type_val,
                "networkTypeName": net_type_str,
                "networkNumber": net_number,
                "macAddress": mac_display,
            }

            # Read MS/TP-specific properties if this is an MS/TP port (type 2)
            if net_type_val == 2:
                max_master = await _read_uint(port_obj_id, "maxMaster", target_addr)
                max_info_frames = await _read_uint(port_obj_id, "maxInfoFrames", target_addr)
                slave_proxy = await _read_bool(port_obj_id, "slaveProxyEnable", target_addr)
                auto_slave_discovery = await _read_bool(
                    port_obj_id, "autoSlaveDiscovery", target_addr
                )

                port_info.update(
                    {
                        "maxMaster": max_master,
                        "maxInfoFrames": max_info_frames,
                        "slaveProxyEnable": slave_proxy,
                        "autoSlaveDiscovery": auto_slave_discovery,
                    }
                )
                mstp_ports.append(port_info)

            network_ports.append(port_info)

        # Display all discovered ports
        if network_ports:
            self.logger.success(f"    Found {len(network_ports)} network port(s):")
            for port in network_ports:
                net_info = (
                    f"Network {port['networkNumber']}"
                    if port["networkNumber"] is not None
                    else "No network"
                )
                mac_info = f", MAC={port['macAddress']}" if port["macAddress"] else ""
                self.logger.display(
                    f"      Port {port['instance']}: {port['name']} - "
                    f"{port['networkTypeName']} - {net_info}{mac_info}"
                )
                if port["networkType"] == 2:
                    mm = port.get("maxMaster")
                    mif = port.get("maxInfoFrames")
                    sp = port.get("slaveProxyEnable")
                    asd = port.get("autoSlaveDiscovery")
                    details = []
                    if mm is not None:
                        details.append(f"maxMaster={mm}")
                    if mif is not None:
                        details.append(f"maxInfoFrames={mif}")
                    if sp is not None:
                        details.append(f"slaveProxy={'enabled' if sp else 'disabled'}")
                    if asd is not None:
                        details.append(f"autoSlaveDiscovery={'enabled' if asd else 'disabled'}")
                    if details:
                        self.logger.display(f"        MS/TP config: {', '.join(details)}")
        else:
            self.logger.display("    No network-port objects found (device may not be a router)")
            self.logger.display("  MS/TP discovery requires a BACnet router target")
            return

        if not mstp_ports:
            self.logger.display("\n    No MS/TP network ports found on this device")
            self.logger.display("    Device has network ports but none are MS/TP (type 2)")
            return

        self.logger.success(
            f"    Found {len(mstp_ports)} MS/TP port(s) — proceeding with segment discovery"
        )

        # ══════════════════════════════════════════════════════════════════════
        # Phase 2: MS/TP Segment Discovery
        # ══════════════════════════════════════════════════════════════════════
        self.logger.display("\n  Phase 2: Discovering devices on MS/TP segments...")

        all_mstp_devices = {}  # {(net_number, mac_addr): device_info}

        for mstp_port in mstp_ports:
            net_num = mstp_port.get("networkNumber")
            if net_num is None:
                self.logger.display(
                    f"    Skipping port {mstp_port['instance']} ({mstp_port['name']}): "
                    f"no network number assigned"
                )
                continue

            max_master = mstp_port.get("maxMaster")
            if max_master is None:
                max_master = 127  # BACnet default
                self.logger.display(
                    f"    Port {mstp_port['instance']}: maxMaster unknown, using default 127"
                )

            self.logger.display(
                f"\n    Scanning MS/TP network {net_num} "
                f"(port {mstp_port['instance']}: {mstp_port['name']}, "
                f"maxMaster={max_master})..."
            )

            # Step 2a: Send Who-Is targeted at the specific network via the router
            self.logger.display(f"      Sending Who-Is broadcast to network {net_num}...")
            try:
                who_is = WhoIsRequest()
                # Target the broadcast address on the remote network
                # In bacpypes3, Address("net:255") sends to broadcast on that DNET
                try:
                    who_is.pduDestination = Address(f"{net_num}:*")
                except Exception:
                    try:
                        who_is.pduDestination = Address(f"{net_num}:255")
                    except Exception:
                        self.logger.debug(
                            f"      Could not create remote broadcast address for "
                            f"network {net_num}, using router address"
                        )
                        who_is.pduDestination = target_addr

                try:
                    response = await asyncio.wait_for(app.request(who_is), timeout=timeout)
                    if response and not isinstance(response, error_types):
                        self.logger.display(f"      Who-Is response: {response}")
                except asyncio.TimeoutError as e:
                    self.logger.debug(f"read bytes failed: {e}")
                    self.logger.display(
                        "      Who-Is broadcast timed out (MS/TP devices may be slow)"
                    )
                except Exception as e:
                    self.logger.debug(f"      Who-Is error on network {net_num}: {e}")
            except Exception as e:
                self.logger.debug(f"      Who-Is request creation error: {e}")

            # Allow extra time for MS/TP token-passing responses
            await asyncio.sleep(min(timeout, 2.0))

            # Step 2b: Probe individual MS/TP addresses 0..maxMaster
            self.logger.display(
                f"      Probing MS/TP addresses 0-{max_master} on network {net_num}..."
            )
            found_on_segment = 0

            for mac_addr in range(0, max_master + 1):
                # Construct address for remote station: "DNET:DADR"
                # MS/TP MAC addresses are 1 byte (0-254)
                try:
                    remote_addr = Address(f"{net_num}:{mac_addr}")
                except Exception as e:
                    self.logger.debug(f"      Cannot create address {net_num}:{mac_addr}: {e}")
                    continue

                # Try to read objectName from device object at this address
                # We use a short timeout since most addresses will be empty
                probe_timeout = min(timeout, 1.5)

                try:
                    # First, try reading the device object at the standard instance
                    # We don't know the device instance, so try reading objectIdentifier
                    # from the well-known "device" object type with a Who-Is to that address
                    probe_request = WhoIsRequest()
                    probe_request.pduDestination = remote_addr

                    try:
                        probe_response = await asyncio.wait_for(
                            app.request(probe_request), timeout=probe_timeout
                        )
                        if probe_response and not isinstance(probe_response, error_types):
                            # Extract device ID from I-Am response
                            remote_device_id = None
                            if hasattr(probe_response, "iAmDeviceIdentifier"):
                                iam_id = probe_response.iAmDeviceIdentifier
                                if hasattr(iam_id, "value"):
                                    remote_device_id = (
                                        iam_id.value[1]
                                        if isinstance(iam_id.value, (tuple, list))
                                        else iam_id.value
                                    )
                                elif isinstance(iam_id, (tuple, list)):
                                    remote_device_id = iam_id[1]
                                else:
                                    remote_device_id = iam_id

                            max_apdu = None
                            if hasattr(probe_response, "maxAPDULengthAccepted"):
                                max_apdu_val = probe_response.maxAPDULengthAccepted
                                if hasattr(max_apdu_val, "value"):
                                    max_apdu = max_apdu_val.value
                                else:
                                    max_apdu = max_apdu_val

                            seg_supported = None
                            if hasattr(probe_response, "segmentationSupported"):
                                seg_val = probe_response.segmentationSupported
                                if hasattr(seg_val, "value"):
                                    seg_supported = seg_val.value
                                else:
                                    seg_supported = seg_val

                            vendor_id = None
                            if hasattr(probe_response, "vendorID"):
                                vid = probe_response.vendorID
                                if hasattr(vid, "value"):
                                    vendor_id = vid.value
                                else:
                                    vendor_id = vid

                            device_info = {
                                "networkNumber": net_num,
                                "macAddress": mac_addr,
                                "deviceId": remote_device_id,
                                "maxApduLengthAccepted": max_apdu,
                                "segmentationSupported": seg_supported,
                                "vendorId": vendor_id,
                            }

                            all_mstp_devices[(net_num, mac_addr)] = device_info
                            found_on_segment += 1

                            self.logger.success(
                                f"      [+] Device at {net_num}:{mac_addr}"
                                f" (device ID={remote_device_id},"
                                f" vendor={vendor_id},"
                                f" maxAPDU={max_apdu})"
                            )
                    except asyncio.TimeoutError as e:
                        # No device at this address — expected for most addresses
                        self.logger.debug(f"read bytes failed: {e}")
                        continue
                    except Exception as e:
                        self.logger.debug(f"      Probe {net_num}:{mac_addr} error: {e}")
                        continue

                except Exception as e:
                    self.logger.debug(f"      Address probe error {net_num}:{mac_addr}: {e}")
                    continue

            self.logger.display(
                f"      Segment scan complete: {found_on_segment} device(s) "
                f"found on network {net_num}"
            )

        if not all_mstp_devices:
            self.logger.display("\n    No MS/TP devices discovered on any segment")
            self.logger.display(
                "    Possible reasons: devices offline, router not forwarding, "
                "or network numbers misconfigured"
            )
            # Still report Phase 4 security findings from Phase 1 data
            self._mstp_report_security(mstp_ports, all_mstp_devices, security_findings)
            return

        # ══════════════════════════════════════════════════════════════════════
        # Phase 3: Remote Device Enumeration
        # ══════════════════════════════════════════════════════════════════════
        self.logger.display(f"\n  Phase 3: Enumerating {len(all_mstp_devices)} MS/TP device(s)...")

        for (net_num, mac_addr), dev_info in all_mstp_devices.items():
            remote_device_id = dev_info.get("deviceId")
            if remote_device_id is None:
                self.logger.display(
                    f"    {net_num}:{mac_addr} — skipping enumeration (no device ID)"
                )
                continue

            self.logger.display(
                f"\n    Enumerating device {remote_device_id} at {net_num}:{mac_addr}..."
            )

            try:
                remote_addr = Address(f"{net_num}:{mac_addr}")
            except Exception as e:
                self.logger.debug(f"    Cannot create address for enumeration: {e}")
                continue

            remote_dev_obj = ObjectIdentifier(("device", remote_device_id))

            # Read objectName
            obj_name = await _read_string(
                remote_dev_obj, "objectName", remote_addr, min(timeout, 5.0)
            )
            if obj_name:
                dev_info["objectName"] = obj_name
                self.logger.display(f"      objectName: {obj_name}")

            # Read vendorIdentifier (in case I-Am didn't have it)
            if dev_info.get("vendorId") is None:
                vendor_id = await _read_uint(
                    remote_dev_obj, "vendorIdentifier", remote_addr, min(timeout, 5.0)
                )
                if vendor_id is not None:
                    dev_info["vendorId"] = vendor_id

            # Read vendorName
            vendor_name = await _read_string(
                remote_dev_obj, "vendorName", remote_addr, min(timeout, 5.0)
            )
            if vendor_name:
                dev_info["vendorName"] = vendor_name
                self.logger.display(f"      vendorName: {vendor_name}")

            # Read modelName
            model_name = await _read_string(
                remote_dev_obj, "modelName", remote_addr, min(timeout, 5.0)
            )
            if model_name:
                dev_info["modelName"] = model_name
                self.logger.display(f"      modelName: {model_name}")

            # Read firmwareRevision
            firmware = await _read_string(
                remote_dev_obj, "firmwareRevision", remote_addr, min(timeout, 5.0)
            )
            if firmware:
                dev_info["firmwareRevision"] = firmware
                self.logger.display(f"      firmwareRevision: {firmware}")

            # Read applicationSoftwareVersion
            app_ver = await _read_string(
                remote_dev_obj,
                "applicationSoftwareVersion",
                remote_addr,
                min(timeout, 5.0),
            )
            if app_ver:
                dev_info["applicationSoftwareVersion"] = app_ver
                self.logger.display(f"      applicationSoftwareVersion: {app_ver}")

            # Read maxApduLengthAccepted (confirm from device object directly)
            max_apdu = await _read_uint(
                remote_dev_obj, "maxApduLengthAccepted", remote_addr, min(timeout, 5.0)
            )
            if max_apdu is not None:
                dev_info["maxApduLengthAccepted"] = max_apdu
                self.logger.display(f"      maxApduLengthAccepted: {max_apdu}")
                if max_apdu < 480:
                    self.logger.display(
                        f"        Note: Small APDU limit ({max_apdu}) — "
                        f"typical for constrained MS/TP devices"
                    )

            # Read segmentationSupported
            seg_val = await _read_uint(
                remote_dev_obj, "segmentationSupported", remote_addr, min(timeout, 5.0)
            )
            if seg_val is not None:
                seg_names = {
                    0: "segmented-both",
                    1: "segmented-transmit",
                    2: "segmented-receive",
                    3: "no-segmentation",
                }
                seg_name = seg_names.get(seg_val, f"unknown({seg_val})")
                dev_info["segmentationSupported"] = seg_name
                self.logger.display(f"      segmentationSupported: {seg_name}")
                if seg_val == 3:
                    self.logger.display("        Note: No segmentation — large reads will fail")

            # Read description
            description = await _read_string(
                remote_dev_obj, "description", remote_addr, min(timeout, 5.0)
            )
            if description:
                dev_info["description"] = description
                self.logger.display(f"      description: {description}")

            # Read protocolVersion and protocolRevision
            proto_ver = await _read_uint(
                remote_dev_obj, "protocolVersion", remote_addr, min(timeout, 5.0)
            )
            proto_rev = await _read_uint(
                remote_dev_obj, "protocolRevision", remote_addr, min(timeout, 5.0)
            )
            if proto_ver is not None:
                dev_info["protocolVersion"] = proto_ver
                ver_str = f"{proto_ver}"
                if proto_rev is not None:
                    dev_info["protocolRevision"] = proto_rev
                    ver_str += f".{proto_rev}"
                self.logger.display(f"      protocolVersion: {ver_str}")

        # ══════════════════════════════════════════════════════════════════════
        # Phase 4: Results Summary
        # ══════════════════════════════════════════════════════════════════════
        self._mstp_report_security(mstp_ports, all_mstp_devices, security_findings)

    def _mstp_report_security(self, mstp_ports, all_mstp_devices, security_findings):
        """Generate the Phase 4 summary and security findings for MS/TP discovery.

        This is a synchronous helper called at the end of _bacpypes3_discover_mstp
        to keep the reporting logic separated from the async discovery flow.
        """
        self.logger.display("\n  Phase 4: MS/TP Discovery Summary")
        self.logger.display("  " + "=" * 60)

        # ── Network topology ──
        self.logger.display("\n  Network Topology:")
        segments = {}  # net_num -> list of devices
        for (net_num, mac_addr), dev_info in all_mstp_devices.items():
            segments.setdefault(net_num, []).append((mac_addr, dev_info))

        for mstp_port in mstp_ports:
            net_num = mstp_port.get("networkNumber")
            mm = mstp_port.get("maxMaster", "?")
            sp = mstp_port.get("slaveProxyEnable")
            port_label = (
                f"    Router port {mstp_port['instance']} ({mstp_port['name']}) "
                f"-> MS/TP network {net_num} (maxMaster={mm})"
            )
            self.logger.display(port_label)

            if net_num is not None and net_num in segments:
                for mac_addr, dev_info in sorted(segments[net_num], key=lambda x: x[0]):
                    dev_id = dev_info.get("deviceId", "?")
                    obj_name = dev_info.get("objectName", "")
                    model = dev_info.get("modelName", "")
                    label = f"      [{net_num}:{mac_addr}] Device {dev_id}"
                    if obj_name:
                        label += f" - {obj_name}"
                    if model:
                        label += f" ({model})"
                    self.logger.display(label)
            else:
                self.logger.display("      (no devices discovered)")

        # ── Device summary table ──
        if all_mstp_devices:
            self.logger.display(f"\n  Discovered {len(all_mstp_devices)} MS/TP device(s) total:")
            for (net_num, mac_addr), dev_info in sorted(all_mstp_devices.items()):
                dev_id = dev_info.get("deviceId", "?")
                obj_name = dev_info.get("objectName", "unknown")
                vendor_name = dev_info.get("vendorName", "")
                model = dev_info.get("modelName", "")
                max_apdu = dev_info.get("maxApduLengthAccepted", "?")
                seg = dev_info.get("segmentationSupported", "?")

                self.logger.display(
                    f"    {net_num}:{mac_addr} | ID={dev_id} | "
                    f"{obj_name} | {vendor_name} {model} | "
                    f"maxAPDU={max_apdu} | seg={seg}"
                )

        # ── Security findings ──
        self.logger.display("\n  Security Assessment:")

        # Check: MS/TP networks have no authentication
        if mstp_ports:
            security_findings.append(
                "MS/TP segments have no built-in authentication — "
                "any device on the RS-485 bus can participate"
            )

        # Check: Slave proxy enabled (pivot point)
        for port in mstp_ports:
            sp = port.get("slaveProxyEnable")
            if sp:
                security_findings.append(
                    f"Port {port['instance']} ({port['name']}): slaveProxyEnable=True — "
                    f"router proxies for slave devices, potential pivot point for "
                    f"IP-to-MS/TP attacks"
                )

        # Check: Large maxMaster values (unnecessary exposure)
        for port in mstp_ports:
            mm = port.get("maxMaster")
            if mm is not None and mm > 31:
                actual_devices = 0
                net_num = port.get("networkNumber")
                if net_num is not None:
                    actual_devices = len(
                        [d for (n, _), d in all_mstp_devices.items() if n == net_num]
                    )
                security_findings.append(
                    f"Port {port['instance']} ({port['name']}): maxMaster={mm} "
                    f"but only {actual_devices} device(s) found — "
                    f"reducing maxMaster limits token-passing exposure"
                )

        # Check: Devices responding to Who-Is from remote networks
        if all_mstp_devices:
            security_findings.append(
                f"{len(all_mstp_devices)} MS/TP device(s) respond to Who-Is from "
                f"remote (IP) network — no network-level isolation"
            )

        # Check: Constrained devices (small APDU / no segmentation)
        for (net_num, mac_addr), dev_info in all_mstp_devices.items():
            max_apdu = dev_info.get("maxApduLengthAccepted")
            seg = dev_info.get("segmentationSupported")
            if max_apdu is not None and max_apdu < 128:
                security_findings.append(
                    f"Device {dev_info.get('deviceId', '?')} at {net_num}:{mac_addr}: "
                    f"very small APDU limit ({max_apdu} bytes) — highly constrained, "
                    f"may be vulnerable to oversized-PDU attacks"
                )
            if seg and "no-segmentation" in str(seg):
                dev_label = dev_info.get("objectName", f"device {dev_info.get('deviceId', '?')}")
                security_findings.append(
                    f"{dev_label} at {net_num}:{mac_addr}: no segmentation support — "
                    f"cannot handle fragmented requests"
                )

        if security_findings:
            for finding in security_findings:
                self.logger.warning(f"    [!] {finding}")
        else:
            self.logger.display("    No specific security concerns identified")

        self.logger.display("\n  " + "=" * 60)
