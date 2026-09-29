"""
KNX Discovery Mixin

Handles gateway discovery, device scanning, bus traffic monitoring, and routing tests.
"""

import asyncio
from datetime import datetime
from typing import Any, Dict, List, TYPE_CHECKING

import logging

logger = logging.getLogger(__name__)


if TYPE_CHECKING:
    from xknx import XKNX

from oida.protocols.knx.constants import _xknx_cls  # noqa: E402
from oida.protocols.knx.cemi_handler import CustomCEMIHandler
from oida.utils import ics_logger as module, ProgressTracker


class DiscoveryMixin:
    """Mixin providing discovery operations."""

    async def _get_gateway_info(self, knx: "XKNX") -> Dict[str, Any]:
        """Get KNX gateway information"""
        self.logger.debug("Retrieving gateway connection details")
        info = {}

        try:
            # xknx ConnectionManager exposes connection_type (the previous
            # `.connection` attribute does not exist on xknx 3.15, so this whole
            # block used to AttributeError and return Unknown).
            cm = getattr(knx, "connection_manager", None)
            if cm is not None:
                info["connection_type"] = str(getattr(cm, "connection_type", "") or "")

            host, port = self.get_target_info()
            self.logger.display(f"KNX Gateway: {host}:{port}")

        except Exception as e:
            self.logger.debug(f"Error getting gateway info: {e}")

        return info

    async def _discover_devices(self, knx: "XKNX") -> List[Dict[str, Any]]:
        """Discover KNX devices on the network using nm_individual_address_check"""
        devices = []

        try:
            # Check for specific individual address first
            individual_addr = self.args.get("individual-address")
            self.logger.debug(f"_discover_devices: individual_addr={individual_addr}")
            if individual_addr:
                device_addresses = [individual_addr]
                self.logger.display(f"Probing specific device: {individual_addr}")
            else:
                # Parse device range (use --scan-range or default)
                scan_range = self.args.get("scan-range", "1.1.1-1.1.255")
                device_addresses = self._parse_device_range(scan_range)
                self.logger.display(f"Scanning {len(device_addresses)} device addresses")

            progress = ProgressTracker(len(device_addresses), logger=self.logger)

            for addr_str in device_addresses:
                try:
                    # Use nm_individual_address_check for fast detection
                    is_occupied = await _xknx_cls.nm_individual_address_check(knx, addr_str)
                    if is_occupied:
                        device_info = {
                            "address": addr_str,
                            "accessible": True,
                            "discovery_method": "nm_individual_address_check",
                        }
                        devices.append(device_info)
                        self.logger.success(f"Found device: {addr_str}")

                except Exception as e:
                    self.logger.debug(f"Error probing device {addr_str}: {e}")

                progress.update()

            self.logger.display(f"Discovered {len(devices)} KNX devices")

        except Exception as e:
            self.logger.fail(f"Error discovering devices: {e}")

        return devices

    async def _listen_bus_traffic(self, knx: "XKNX", duration: int = 30) -> Dict[str, Any]:
        """Passive bus traffic monitoring - listens without sending probes"""
        self.logger.debug(f"Passive bus listen: duration={duration}s")
        traffic_data: Dict[str, Any] = {
            "duration": duration,
            "telegrams": [],
            "group_addresses": {},
            "devices": set(),
        }

        try:
            self.logger.display(f"Listening for bus traffic ({duration}s)...")

            received_telegrams = []

            # xknx 3.20 TelegramQueue._run_telegram_received_cbs invokes the
            # callback synchronously (callback.callback(telegram), never
            # awaited), so an `async def` here returns a coroutine nobody
            # runs - the capture body silently never executes.
            def telegram_received(telegram):
                if telegram.destination_address:
                    tg_info = {
                        "destination": str(telegram.destination_address),
                        "source": str(telegram.source_address),
                        "payload": str(telegram.payload) if telegram.payload else "",
                        "timestamp": datetime.now().isoformat(),
                    }
                    received_telegrams.append(tg_info)

                    # Live output
                    src = tg_info["source"]
                    dst = tg_info["destination"]
                    payload = tg_info["payload"][:40] if tg_info["payload"] else ""
                    self.logger.success(f"  {src} -> {dst}  {payload}")

            # Register listener
            knx.telegram_queue.register_telegram_received_cb(telegram_received)

            # Listen for specified duration with progress display
            for remaining in range(duration, 0, -1):
                if remaining % 10 == 0 or remaining <= 5:
                    self.logger.debug(f"Listening... {remaining}s remaining")
                await asyncio.sleep(1)

            # Process results
            traffic_data["telegrams"] = received_telegrams

            # Build group address and device summary
            for tg in received_telegrams:
                src = tg["source"]
                dst = tg["destination"]
                traffic_data["devices"].add(src)

                if dst not in traffic_data["group_addresses"]:
                    traffic_data["group_addresses"][dst] = {"sources": set(), "count": 0}
                traffic_data["group_addresses"][dst]["sources"].add(src)
                traffic_data["group_addresses"][dst]["count"] += 1

            # Convert sets to lists for JSON serialization
            traffic_data["devices"] = list(traffic_data["devices"])
            for ga in traffic_data["group_addresses"].values():
                ga["sources"] = list(ga["sources"])

            # Summary
            num_telegrams = len(received_telegrams)
            num_devices = len(traffic_data["devices"])
            num_groups = len(traffic_data["group_addresses"])

            if num_telegrams > 0:
                self.logger.display(
                    f"Captured {num_telegrams} telegrams from {num_devices} devices to {num_groups} group addresses"
                )
            else:
                self.logger.display("No bus traffic captured")

        except Exception as e:
            self.logger.fail(f"Error listening to bus traffic: {e}")

        return traffic_data

    async def _discover_gateways(self, knx: "XKNX") -> List[Dict[str, Any]]:
        """Discover KNX/IP gateways via multicast and unicast with full device info"""
        self.logger.debug("Starting gateway discovery (unicast + multicast)")
        gateways = []
        found_gateways = {}

        # Get target info for unicast query
        host, port = self.get_target_info()

        try:
            # First, try direct unicast query to target (works for remote gateways)
            self.logger.display(f"Querying KNX gateway at {host}:{port}...")
            extended_info = await self._get_gateway_extended_info(host, port)

            if extended_info and extended_info.get("name"):
                gateway_info = {
                    "name": extended_info.get("name", "Unknown"),
                    "ip": host,
                    "port": port,
                    "individual_address": extended_info.get("individual_address"),
                    "supports_tunnelling": "TUNNELING"
                    in extended_info.get("supported_services", {}),
                    "supports_routing": "ROUTING" in extended_info.get("supported_services", {}),
                    "supports_tunnelling_tcp": False,
                    "supports_secure": False,
                    "mac_address": extended_info.get("mac_address"),
                    "serial_number": extended_info.get("serial_number"),
                    "multicast_address": extended_info.get("multicast_address"),
                    "knx_medium": extended_info.get("knx_medium"),
                    "programming_mode": extended_info.get("programming_mode", False),
                    "supported_services": extended_info.get("supported_services", {}),
                }
                found_gateways[host] = gateway_info
                self.logger.success(f"Found gateway via unicast: {gateway_info['name']}")

            # Also try multicast discovery for local network gateways
            self.logger.display("Scanning for KNX/IP gateways via multicast...")
            scanner = _xknx_cls.GatewayScanner(knx, timeout_in_seconds=5)

            async for gateway in scanner.async_scan():
                if gateway.ip_addr not in found_gateways:
                    gateway_info = {
                        "name": gateway.name,
                        "ip": gateway.ip_addr,
                        "port": gateway.port,
                        "individual_address": (
                            str(gateway.individual_address) if gateway.individual_address else None
                        ),
                        "supports_tunnelling": gateway.supports_tunnelling,
                        "supports_routing": gateway.supports_routing,
                        "supports_tunnelling_tcp": getattr(
                            gateway, "supports_tunnelling_tcp", False
                        ),
                        "supports_secure": getattr(gateway, "supports_secure", False),
                        "mac_address": None,
                        "serial_number": None,
                        "multicast_address": None,
                        "knx_medium": None,
                        "programming_mode": False,
                        "supported_services": {},
                    }
                    found_gateways[gateway.ip_addr] = gateway_info

            # Enrich multicast-discovered gateways with extended info
            for ip, gw_info in found_gateways.items():
                if not gw_info.get("mac_address"):
                    try:
                        extended_info = await self._get_gateway_extended_info(ip, gw_info["port"])
                        if extended_info:
                            gw_info.update(extended_info)
                    except Exception as e:
                        self.logger.debug(f"Could not get extended info for {ip}: {e}")

                gateways.append(gw_info)

                # Display gateway info
                self.logger.display(f"KNX Gateway at {gw_info['ip']}:{gw_info['port']}")
                self.logger.display(f"  Friendly Name: {gw_info['name']}")
                if gw_info.get("mac_address"):
                    mac = gw_info["mac_address"]
                    vendor_name = module.mac_lookup(mac, full=True)
                    self.logger.display(f"  MAC Address: {mac}")
                    if vendor_name:
                        self.logger.display(f"  MAC Vendor: {vendor_name}")
                        gw_info["mac_vendor"] = vendor_name
                if gw_info.get("serial_number"):
                    self.logger.display(f"  Serial: {gw_info['serial_number']}")
                if gw_info.get("individual_address"):
                    self.logger.display(f"  KNX Address: {gw_info['individual_address']}")
                if gw_info.get("multicast_address"):
                    self.logger.display(f"  Multicast: {gw_info['multicast_address']}")
                if gw_info.get("supported_services"):
                    self.logger.display(
                        f"  Services: {', '.join(f'{k} v{v}' for k, v in gw_info['supported_services'].items())}"
                    )
                self.logger.display(
                    f"  Tunnelling: {gw_info['supports_tunnelling']}, Routing: {gw_info['supports_routing']}"
                )

            self.logger.display(f"Discovered {len(gateways)} KNX/IP gateways")

        except Exception as e:
            self.logger.fail(f"Error scanning for gateways: {e}")

        return gateways

    async def _get_gateway_extended_info(self, ip: str, port: int) -> Dict[str, Any]:
        """Get extended gateway info via direct description request"""
        import socket
        from xknx.knxip import HPAI, KNXIPFrame, DescriptionRequest, DescriptionResponse
        from xknx.knxip.dib import DIBDeviceInformation, DIBSuppSVCFamilies, DIBServiceFamily

        self.logger.debug(f"Requesting extended info from {ip}:{port}")
        info = {}

        # NAT mode is on by default; --no-nat opts out.
        use_nat = not self.args.get("no-nat", False)
        self.logger.debug(f"NAT mode: {use_nat}")

        # TODO: Raw UDP KNXnet/IP tunnelling - xknx handles connection
        # management natively. Replace manual socket + packet construction
        # with xknx.io.KNXIPInterface for tunnelling connections.
        sock = None
        try:
            # Create UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Connect to gateway
            sock.connect((ip, port))
            local_addr = sock.getsockname()

            # Create description request
            if use_nat:
                # NAT mode: use 0.0.0.0:0 - gateway responds to packet source
                desc_request = DescriptionRequest(control_endpoint=HPAI())
            else:
                # Non-NAT mode: specify local IP and port explicitly
                desc_request = DescriptionRequest(
                    control_endpoint=HPAI(ip_addr=local_addr[0], port=local_addr[1])
                )
            frame = KNXIPFrame.init_from_body(desc_request)

            # Send to gateway
            sock.send(bytes(frame.to_knx()))

            # Wait for response
            try:
                data = sock.recv(1024)
                response_frame, _ = KNXIPFrame.from_knx(data)

                if isinstance(response_frame.body, DescriptionResponse):
                    # Parse DIBs
                    for dib in response_frame.body.dibs:
                        if isinstance(dib, DIBDeviceInformation):
                            info["name"] = dib.name
                            info["individual_address"] = (
                                str(dib.individual_address) if dib.individual_address else None
                            )
                            info["mac_address"] = dib.mac_address.upper()
                            info["serial_number"] = dib.serial_number.replace(":", "")
                            info["multicast_address"] = dib.multicast_address
                            info["knx_medium"] = str(dib.knx_medium)
                            info["programming_mode"] = dib.programming_mode
                        elif isinstance(dib, DIBSuppSVCFamilies):
                            services = {}
                            for svc in [
                                DIBServiceFamily.CORE,
                                DIBServiceFamily.DEVICE_MANAGEMENT,
                                DIBServiceFamily.TUNNELING,
                                DIBServiceFamily.ROUTING,
                            ]:
                                ver = dib.version(svc)
                                if ver:
                                    services[svc.name] = ver
                            info["supported_services"] = services

            except TimeoutError:
                self.logger.debug(f"Timeout waiting for description response from {ip}")

        except Exception as e:
            self.logger.debug(f"Error getting extended gateway info: {e}")
        finally:
            if sock:
                try:
                    sock.close()
                except Exception as e:
                    logger.debug(f"sock.close(): {e}")  # Socket cleanup errors are safe to ignore

        return info

    async def _scan_bus_devices(self, knx: "XKNX", scan_range: str) -> List[Dict[str, Any]]:
        """Scan bus for devices using nm_individual_address_check"""
        self.logger.debug(f"Slow bus scan: range={scan_range}")
        devices = []

        # Use parse_bus_ranges which handles comma-separated ranges correctly
        from oida.protocols.knx.helpers import parse_bus_ranges

        device_addresses = [str(a) for a in parse_bus_ranges(scan_range)]

        try:
            self.logger.display(f"Bus scan: checking {len(device_addresses)} addresses")

            for addr_str in device_addresses:
                try:
                    # Use nm_individual_address_check for fast probing
                    is_occupied = await _xknx_cls.nm_individual_address_check(knx, addr_str)
                    if is_occupied:
                        devices.append(
                            {
                                "address": addr_str,
                                "accessible": True,
                                "discovery_method": "nm_individual_address_check",
                            }
                        )
                        self.logger.success(f"Found device: {addr_str}")
                except Exception as e:
                    self.logger.debug(f"Error checking {addr_str}: {e}")
                    continue

            self.logger.display(f"Bus scan complete: found {len(devices)} devices")

        except Exception as e:
            self.logger.fail(f"Error in bus scan: {e}")

        return devices

    async def _read_group_address(self, knx: "XKNX", group_addr: str) -> Dict[str, Any]:
        """Read value from a specific group address"""
        from xknx.telegram import GroupAddress
        from xknx.devices import Sensor

        self.logger.debug(f"Reading group address: {group_addr}")
        result = {"address": group_addr, "value": None, "raw": None, "error": None}

        try:
            self.logger.display(f"Reading group address: {group_addr}")
            ga = GroupAddress(group_addr)

            # Create a sensor to read the value
            sensor = Sensor(
                knx,
                name="group_read",
                group_address_state=ga,
            )

            # Sync to request current value
            await sensor.sync()

            # Wait briefly for response
            await asyncio.sleep(2)

            # Get the value
            if sensor.sensor_value.value is not None:
                result["value"] = sensor.sensor_value.value
                result["raw"] = (
                    str(sensor.sensor_value.last_payload)
                    if sensor.sensor_value.last_payload
                    else None
                )
                self.logger.success(f"Group {group_addr} value: {result['value']}")
            else:
                result["error"] = "No response received"
                self.logger.warning(f"Group {group_addr}: No response")

        except Exception as e:
            result["error"] = str(e)
            self.logger.debug(f"Error reading group address {group_addr}: {e}")

        return result

    async def _find_device_by_serial(self, knx: "XKNX", serial_hex: str) -> Dict[str, Any]:
        """Find device by serial number using IndividualAddressSerialRead"""
        self.logger.debug(f"Serial scan: searching for serial={serial_hex}")
        result = {
            "serial": serial_hex,
            "address": None,
            "success": False,
            "error": None,
        }

        try:
            # Parse and validate serial (should be 6 bytes = 12 hex chars)
            serial_hex = serial_hex.strip().upper()
            if len(serial_hex) != 12:
                raise ValueError(f"Serial must be 12 hex chars (6 bytes), got {len(serial_hex)}")

            serial_bytes = bytes.fromhex(serial_hex)
            self.logger.display(f"Searching for device with serial {serial_hex}...")

            # Send broadcast IndividualAddressSerialRead
            # Use broadcast address 0.0.0 for the request
            mgmt = knx.management

            # We need to send to broadcast and listen for response
            # The response contains the individual address of the device with that serial
            broadcast_addr = _xknx_cls.IndividualAddress("0.0.0")

            async with mgmt.connection(broadcast_addr) as p2p:
                try:
                    resp = await asyncio.wait_for(
                        p2p.request(
                            _xknx_cls.IndividualAddressSerialRead(serial=serial_bytes),
                            _xknx_cls.IndividualAddressSerialResponse,
                        ),
                        timeout=5.0,
                    )

                    if resp and resp.payload:
                        # The response should contain the individual address
                        found_addr = getattr(resp.payload, "address", None)
                        if found_addr:
                            result["address"] = str(found_addr)
                            result["success"] = True
                            self.logger.success(f"  Found device: {result['address']}")
                        else:
                            result["error"] = "Response received but no address"
                            self.logger.fail("  Device not found (no address in response)")
                    else:
                        result["error"] = "No response"
                        self.logger.fail(f"  Device with serial {serial_hex} not found")

                except asyncio.TimeoutError:
                    result["error"] = "Timeout - no device responded"
                    self.logger.fail("  No device responded (timeout)")

        except Exception as e:
            result["error"] = str(e)
            self.logger.fail(f"Error searching by serial: {e}")

        return result

    async def _read_domain_by_serial(self, knx: "XKNX", serial_hex: str) -> Dict[str, Any]:
        """Read a Powerline/RF device's domain address by serial number.

        Sends a broadcast ``A_DomainAddress_SerialNumber_Read`` (xknx
        ``DomainAddressSerialNumberRead``, available since xknx 3.17); the device
        with the matching 6-byte serial replies with its domain address. This is
        how PL110 / RF devices are addressed - the domain address is their
        medium-level network id - so it reaches the bus *behind* a KNX IP
        interface that our individual-address probes cannot.
        """
        self.logger.debug(f"Domain-address serial read: serial={serial_hex}")
        result = {
            "serial": serial_hex,
            "domain_address": None,
            "success": False,
            "error": None,
        }

        try:
            serial_hex = serial_hex.strip().upper()
            if len(serial_hex) != 12:
                raise ValueError(f"Serial must be 12 hex chars (6 bytes), got {len(serial_hex)}")
            serial_bytes = bytes.fromhex(serial_hex)

            self.logger.display(f"Reading domain address for serial {serial_hex}...")
            mgmt = knx.management
            broadcast_addr = _xknx_cls.IndividualAddress("0.0.0")

            async with mgmt.connection(broadcast_addr) as p2p:
                try:
                    resp = await asyncio.wait_for(
                        p2p.request(
                            _xknx_cls.DomainAddressSerialNumberRead(serial=serial_bytes),
                            _xknx_cls.DomainAddressSerialNumberResponse,
                        ),
                        timeout=5.0,
                    )

                    if resp and resp.payload is not None:
                        domain = getattr(resp.payload, "domain_address", None)
                        if domain:
                            result["domain_address"] = bytes(domain).hex().upper()
                            result["success"] = True
                            self.logger.success(
                                f"  Serial {serial_hex} -> domain address "
                                f"0x{result['domain_address']}"
                            )
                        else:
                            result["error"] = "Response received but no domain address"
                            self.logger.fail("  No domain address in response")
                    else:
                        result["error"] = "No response"
                        self.logger.fail(f"  No device responded for serial {serial_hex}")

                except asyncio.TimeoutError:
                    result["error"] = "Timeout - no device responded"
                    self.logger.fail("  No device responded (timeout)")

        except Exception as e:
            result["error"] = str(e)
            self.logger.fail(f"Error reading domain by serial: {e}")

        return result

    async def _test_routing(self, knx: "XKNX") -> Dict[str, Any]:
        """Test KNX routing capabilities"""
        self.logger.debug("Testing routing capabilities")
        routing_test = {"routing_supported": False, "errors": []}

        # Sending the probe telegram is a live write onto the bus, so it is
        # gated behind --confirm like other dangerous KNX operations.
        if not self.args.get("confirm"):
            self.logger.fail("--test-routing requires --confirm flag (DANGEROUS operation)")
            routing_test["error"] = "Missing --confirm flag"
            return routing_test

        try:
            # Test routing by sending a GroupValueWrite telegram. xknx requires
            # an APCI instance as the payload (raw bytes raise ConversionError
            # later inside the queue task, which would not be observable here).
            from xknx.dpt import DPTBinary

            test_telegram = _xknx_cls.Telegram(
                destination_address=_xknx_cls.GroupAddress("0/0/1"),
                source_address=_xknx_cls.IndividualAddress("1.1.0"),
                payload=_xknx_cls.GroupValueWrite(DPTBinary(0)),
            )

            # Only mark routing as supported once the telegram is actually
            # accepted onto the bus (no exception from the send path).
            await knx.telegrams.put(test_telegram)
            routing_test["routing_supported"] = True

        except Exception as e:
            routing_test["errors"].append(str(e))
            self.logger.debug(f"Routing test failed: {e}")

        return routing_test

    async def _fast_bus_scan(
        self, knx: "XKNX", scan_range: str, listen_time: int = 0
    ) -> Dict[str, Any]:
        """Fast bus discovery using CustomCEMIHandler with parallel traffic capture"""
        self.logger.debug(
            f"Fast bus scan: range={scan_range}, listen={listen_time}s, timeout={self.discovery_timeout}s"
        )
        result = {
            "scan_range": scan_range,
            "devices": [],
            "traffic": [],
            "total_found": 0,
            "method": "cemi_tconnect",
            "error": None,
        }

        try:
            self.logger.display(f"Fast bus scan: {scan_range} (timeout: {self.discovery_timeout}s)")
            handler = CustomCEMIHandler(knx, logger=self.logger)

            # Pass listen_time for parallel traffic capture
            scan_result = await handler.fast_bus_discovery(
                scan_range, timeout=self.discovery_timeout, listen_time=listen_time
            )

            # Handle new dict return format
            found_devices = scan_result.get("devices", set())
            captured_traffic = scan_result.get("traffic", [])

            for addr in sorted(found_devices):
                result["devices"].append(
                    {
                        "address": addr,
                        "accessible": True,
                        "discovery_method": "cemi_tconnect",
                    }
                )

            result["traffic"] = captured_traffic
            result["total_found"] = len(result["devices"])

            if result["total_found"] > 0:
                self.logger.display(f"Fast scan: Found {result['total_found']} devices")
            else:
                self.logger.display("Fast scan: No devices responding")

        except Exception as e:
            result["error"] = str(e)
            self.logger.fail(f"Error in fast bus scan: {e}")

        return result
