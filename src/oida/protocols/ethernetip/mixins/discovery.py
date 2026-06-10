"""
EtherNet/IP Discovery Mixin

Handles device discovery commands:
- ListIdentity (0x63) - device identification
- ListServices (0x04) - CIP service enumeration
- ListInterfaces (0x64) - network interface enumeration
- Broadcast discovery via UDP
"""

from __future__ import annotations

import socket
import struct
import time
from typing import Any, Dict, List, TYPE_CHECKING

from ....utils.vendor_maps import ethernetip_vendor_ids as vendor_ids
from ....utils.vendor_maps import ethernetip_device_types as device_types
from ..constants import (
    ENIP_CMD_LIST_IDENTITY,
    ENIP_CMD_LIST_SERVICES,
    ENIP_CMD_LIST_INTERFACES,
)

if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


class DiscoveryMixin(_ScannerBase):
    """Mixin providing EtherNet/IP discovery operations."""

    def _list_identity(
        self,
        host: str,
        port: int = 44818,
        use_udp: bool = False,
        display: bool = True,
    ) -> Dict[str, Any]:
        """
        Send ListIdentity command to get device information.

        Returns device identity including vendor, product, revision, serial number.
        """
        result = {
            "success": False,
            "vendor_id": 0,
            "vendor_name": "Unknown",
            "device_type": 0,
            "product_code": 0,
            "revision": (0, 0),
            "serial_number": 0,
            "product_name": "",
            "state": 0,
        }

        response = self._send_enip_command(host, port, ENIP_CMD_LIST_IDENTITY, use_udp=use_udp)
        if not response:
            return result

        header = self._parse_enip_header(response)
        if not header or header["command"] != ENIP_CMD_LIST_IDENTITY:
            return result

        try:
            # Parse CPF (Common Packet Format) items
            data = header["data"]
            if len(data) < 2:
                return result

            item_count = struct.unpack("<H", data[:2])[0]
            if item_count < 1:
                return result

            # Parse first item (Identity)
            offset = 2
            if len(data) < offset + 4:
                return result

            type_id, item_length = struct.unpack("<HH", data[offset : offset + 4])
            offset += 4

            if type_id != 0x000C:  # Identity item type
                self.logger.debug(f"Unexpected item type: 0x{type_id:04X}")
                return result

            if len(data) < offset + item_length:
                return result

            item_data = data[offset : offset + item_length]

            # Parse identity structure
            # Protocol version (2) + sockaddr (16) + vendor (2) + device type (2) +
            # product code (2) + revision (2) + status (2) + serial (4) + name length (1) + name + state (1)
            if len(item_data) < 33:
                return result

            # Protocol version (2 bytes)
            identity_offset = 2

            # Parse sockaddr structure (16 bytes) to get Device IP
            # sockaddr_in: sin_family (2) + sin_port (2) + sin_addr (4) + sin_zero (8)
            if len(item_data) >= identity_offset + 16:
                # Skip sin_family (2 bytes) and sin_port (2 bytes)
                # IP address is in network byte order (big endian)
                ip_bytes = item_data[identity_offset + 4 : identity_offset + 8]
                result["device_ip"] = ".".join(str(b) for b in ip_bytes)
                identity_offset += 16

            result["vendor_id"] = struct.unpack(
                "<H", item_data[identity_offset : identity_offset + 2]
            )[0]
            result["vendor_name"] = vendor_ids.get(
                result["vendor_id"], f"Vendor_{result['vendor_id']}"
            )
            identity_offset += 2

            result["device_type"] = struct.unpack(
                "<H", item_data[identity_offset : identity_offset + 2]
            )[0]
            result["device_type_name"] = device_types.get(
                result["device_type"], f"Unknown (0x{result['device_type']:02X})"
            )
            identity_offset += 2

            result["product_code"] = struct.unpack(
                "<H", item_data[identity_offset : identity_offset + 2]
            )[0]
            identity_offset += 2

            major, minor = struct.unpack("<BB", item_data[identity_offset : identity_offset + 2])
            result["revision"] = (major, minor)
            identity_offset += 2

            result["status"] = struct.unpack(
                "<H", item_data[identity_offset : identity_offset + 2]
            )[0]
            identity_offset += 2

            result["serial_number"] = struct.unpack(
                "<I", item_data[identity_offset : identity_offset + 4]
            )[0]
            identity_offset += 4

            # Product name (length-prefixed string)
            name_length = item_data[identity_offset]
            identity_offset += 1

            if len(item_data) >= identity_offset + name_length:
                result["product_name"] = item_data[
                    identity_offset : identity_offset + name_length
                ].decode("utf-8", errors="replace")
                identity_offset += name_length

            # State
            if len(item_data) > identity_offset:
                result["state"] = item_data[identity_offset]

            # Interpret state field (CIP Identity Object states - Vol 1, 5-2)
            state_map = {
                0: "Non-existent",
                1: "Device Self Testing",
                2: "Standby",
                3: "Operational",
                4: "Major Recoverable Fault",
                5: "Major Unrecoverable Fault",
                6: "Default for DHCP/BOOTP",
                255: "Default (Unknown)",
            }
            result["state_name"] = state_map.get(result["state"], f"Unknown ({result['state']})")

            # Interpret status word (CIP Identity Object - Vol 1, 5-3)
            # Bits 0-3: Owned, Configured, Extended Device Status 1, Extended Device Status 2
            # Bits 4-7: Minor Recoverable Fault, Minor Unrecoverable Fault, Major Recoverable Fault, Major Unrecoverable Fault
            # Bits 8-11: Extended Device Status (more specific)
            status = result.get("status", 0)
            if status:
                result["status_owned"] = bool(status & 0x0001)
                result["status_configured"] = bool(status & 0x0002)
                result["status_minor_recoverable_fault"] = bool(status & 0x0010)
                result["status_minor_unrecoverable_fault"] = bool(status & 0x0020)
                result["status_major_recoverable_fault"] = bool(status & 0x0040)
                result["status_major_unrecoverable_fault"] = bool(status & 0x0080)
                result["status_faulted"] = bool(status & 0x00F0)  # Any fault bits

                # Extended device status (bits 8-11) - vendor specific interpretation
                extended_status = (status >> 8) & 0x0F
                extended_status_map = {
                    0: "Unknown",
                    1: "Firmware Update In Progress",
                    2: "Firmware Flash In Progress",
                    3: "Device Self Testing",
                    4: "No Network Connection",
                    5: "Firmware Upgrade",
                    6: "Security Mode Change",
                }
                result["extended_status"] = extended_status_map.get(
                    extended_status, f"Unknown ({extended_status})"
                )

            result["success"] = True

            if display:
                self.logger.display(
                    f"ListIdentity: {result['vendor_name']} - {result['product_name']}"
                )
                self.logger.display(f"  Device Type: {result.get('device_type_name', 'Unknown')}")
                self.logger.display(f"  Revision: {result['revision'][0]}.{result['revision'][1]}")
                self.logger.display(f"  Serial: 0x{result['serial_number']:08X}")
                self.logger.display(f"  State: {result.get('state_name', 'Unknown')}")
                if result.get("device_ip"):
                    self.logger.display(f"  Device IP: {result['device_ip']}")
                if result.get("status_faulted"):
                    self.logger.warning(f"  [!] Device has active fault (status: 0x{status:04X})")

        except Exception as e:
            self.logger.debug(f"Error parsing ListIdentity response: {e}")

        return result

    def _parse_cpf_items(self, data: bytes) -> List[tuple]:
        """Parse CPF (Common Packet Format) items from EtherNet/IP response data.

        Returns list of (type_id, item_data) tuples.
        """
        items = []
        if len(data) < 2:
            return items

        item_count = struct.unpack("<H", data[:2])[0]
        offset = 2

        for _ in range(item_count):
            if len(data) < offset + 4:
                break

            type_id, item_length = struct.unpack("<HH", data[offset : offset + 4])
            offset += 4

            if len(data) < offset + item_length:
                break

            item_data = data[offset : offset + item_length]
            offset += item_length
            items.append((type_id, item_data))

        return items

    def _list_services(self, host: str, port: int = 44818) -> List[Dict[str, Any]]:
        """
        Send ListServices command to enumerate CIP services.

        Returns list of available services (e.g., Communications, CIP Encapsulation).
        """
        services = []

        response = self._send_enip_command(host, port, ENIP_CMD_LIST_SERVICES)
        if not response:
            return services

        header = self._parse_enip_header(response)
        if not header or header["command"] != ENIP_CMD_LIST_SERVICES:
            return services

        try:
            for type_id, item_data in self._parse_cpf_items(header["data"]):
                # Parse service item
                if type_id == 0x0100:  # Communications service
                    service = {
                        "type": "Communications",
                        "type_code": type_id,
                    }
                    if len(item_data) >= 4:
                        service["protocol_version"] = struct.unpack("<H", item_data[:2])[0]
                        service["capability_flags"] = struct.unpack("<H", item_data[2:4])[0]
                    if len(item_data) >= 20:
                        service["name"] = (
                            item_data[4:20].decode("utf-8", errors="replace").rstrip("\x00")
                        )

                    services.append(service)
                    self.logger.display(
                        f"Service: {service.get('name', 'Communications')} (0x{type_id:04X})"
                    )
                else:
                    services.append(
                        {
                            "type": "Unknown",
                            "type_code": type_id,
                            "data": item_data.hex(),
                        }
                    )
                    self.logger.debug(f"Unknown service type: 0x{type_id:04X}")

        except Exception as e:
            self.logger.debug(f"Error parsing ListServices response: {e}")

        return services

    def _list_interfaces(self, host: str, port: int = 44818) -> List[Dict[str, Any]]:
        """
        Send ListInterfaces command to enumerate network interfaces.

        Returns list of network interfaces on the target device.
        """
        interfaces = []

        response = self._send_enip_command(host, port, ENIP_CMD_LIST_INTERFACES)
        if not response:
            return interfaces

        header = self._parse_enip_header(response)
        if not header or header["command"] != ENIP_CMD_LIST_INTERFACES:
            return interfaces

        try:
            for i, (type_id, item_data) in enumerate(self._parse_cpf_items(header["data"])):
                interface = {
                    "index": i,
                    "type_code": type_id,
                    "data_length": len(item_data),
                }

                # Try to parse common interface types
                if type_id == 0x000C:  # CIP Identity
                    interface["type"] = "CIP Identity"
                elif type_id == 0x0086:  # Ethernet Link
                    interface["type"] = "Ethernet Link"
                else:
                    interface["type"] = f"Unknown (0x{type_id:04X})"

                if item_data:
                    interface["raw_data"] = item_data.hex()

                interfaces.append(interface)
                self.logger.display(f"Interface {i}: {interface['type']}")

        except Exception as e:
            self.logger.debug(f"Error parsing ListInterfaces response: {e}")

        return interfaces

    def _broadcast_discovery(
        self, lhost: str, port: int = 44818, timeout: float = 3.0
    ) -> List[Dict[str, Any]]:
        """
        Discover EtherNet/IP devices via UDP broadcast.

        Args:
            lhost: Local interface IP to bind to
            port: Target port (44818)
            timeout: Response collection timeout

        Returns:
            List of discovered device identities
        """
        devices = []

        if not lhost:
            self.logger.fail("Broadcast discovery requires --lhost parameter")
            return devices

        self.logger.display(f"Broadcasting ListIdentity from {lhost} to 255.255.255.255:{port}...")

        sock = None
        try:
            # Build ListIdentity packet
            packet = self._build_enip_packet(ENIP_CMD_LIST_IDENTITY)

            # Create UDP socket with broadcast
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((lhost, 0))
            sock.settimeout(0.5)  # Short timeout for individual receives

            # Send broadcast
            sock.sendto(packet, ("255.255.255.255", port))

            # Collect responses
            start_time = time.time()
            seen_ips = set()

            while time.time() - start_time < timeout:
                try:
                    data, addr = sock.recvfrom(4096)
                    ip_addr = addr[0]

                    if ip_addr in seen_ips:
                        continue
                    seen_ips.add(ip_addr)

                    # Parse the response as ListIdentity
                    header = self._parse_enip_header(data)
                    if header and header["command"] == ENIP_CMD_LIST_IDENTITY:
                        # Re-parse as full identity using existing method
                        # We need to manually parse here since _list_identity expects a host
                        device = self._parse_list_identity_response(data)
                        device["ip_address"] = ip_addr
                        devices.append(device)

                        self.logger.display(
                            f"  Found: {ip_addr} - {device.get('vendor_name', 'Unknown')} {device.get('product_name', '')}"
                        )

                except TimeoutError:
                    # Normal: poll window elapsed with no more responses.
                    continue
                except Exception as e:
                    self.logger.debug(f"Error receiving broadcast response: {e}")

        except Exception as e:
            self.logger.debug(f"broadcast discovery failed: {e}")
            self.logger.fail(f"Broadcast discovery failed: {e}")
        finally:
            if sock:
                try:
                    sock.close()
                except Exception as e:
                    self.logger.debug(f"broadcast socket close failed: {e}")

        self.logger.display(f"Discovered {len(devices)} device(s)")
        return devices

    def _parse_list_identity_response(self, data: bytes) -> Dict[str, Any]:
        """Parse a ListIdentity response packet.

        Delegates to the shared ``parse_list_identity`` parser in
        ``parsers.py`` and returns a consistent empty-result dict on failure.
        """
        from ..parsers import parse_list_identity

        parsed = parse_list_identity(data)
        if parsed is not None:
            return parsed

        return {
            "success": False,
            "vendor_id": 0,
            "vendor_name": "Unknown",
            "device_type": 0,
            "product_code": 0,
            "revision": (0, 0),
            "serial_number": 0,
            "product_name": "",
            "state": 0,
        }
