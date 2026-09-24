"""
Industrial Control Systems (ICS) protocol scanners.

Contains:
- KNXScanner: KNX/EIB building automation discovery
- BACnetScanner: BACnet building automation discovery
- EtherNetIPScanner: EtherNet/IP device discovery
- CODESYSScanner: CODESYS V3 PLC discovery
- ADSScanner: Beckhoff ADS/TwinCAT device discovery
"""

import socket
import struct
import threading
import time
from datetime import datetime
from typing import Any, Dict, Optional, Set

from oida.protocols.discovery.core import (
    DiscoveredDevice,
    create_udp_socket,
    get_all_broadcast_addresses,
    get_interface_ip,
    validate_interface,
    validate_subnet,
    validate_timeout,
)
from oida.utils.rate_limiter import sendto
from oida.utils.ics_logger import get_module_logger
from oida.utils.lazy_import import lazy_import

_ethernetip = lazy_import("oida.protocols.ethernetip", "EtherNet/IP")

logger = get_module_logger(__name__)


class KNXScanner:
    """KNX/EIB device discovery via multicast search

    KNX uses multicast on 224.0.23.12:3671 for discovery.
    Sends SearchRequest and listens for SearchResponse.
    """

    KNX_MULTICAST_ADDR = "224.0.23.12"
    KNX_PORT = 3671

    def __init__(self, interface: str, timeout: int = 10):
        self.interface = validate_interface(interface)
        self.timeout = validate_timeout(timeout)
        self.discovered_devices: Dict[str, DiscoveredDevice] = {}
        self._lock = threading.Lock()

    def scan(self) -> Dict[str, DiscoveredDevice]:
        """Send KNXnet/IP SearchRequest and collect responses"""
        # Get interface IP for HPAI field in KNX packet
        local_ip = get_interface_ip(self.interface)
        if not local_ip:
            logger.debug(f"KNX: Could not get IP for {self.interface}, skipping")
            return self.discovered_devices

        try:
            sock = create_udp_socket(self.interface, timeout=2.0, multicast_ttl=1)
            try:
                local_port = sock.getsockname()[1]

                # Build KNXnet/IP SearchRequest
                # Header: size (1), version (1), service type (2), total length (2)
                header = struct.pack(">BBHH", 0x06, 0x10, 0x0201, 14)  # SEARCH_REQUEST

                # HPAI (Host Protocol Address Information)
                # Structure: length (1), protocol (1 = UDP), IP (4), port (2)
                ip_bytes = socket.inet_aton(local_ip)
                hpai = struct.pack(">BB", 8, 0x01) + ip_bytes + struct.pack(">H", local_port)

                search_request = header + hpai

                # Send to multicast (rate-limited)
                sendto(sock, search_request, (self.KNX_MULTICAST_ADDR, self.KNX_PORT))

                # Collect responses (single send only - no resend to avoid OT disruption)
                start_time = time.time()
                while time.time() - start_time < self.timeout:
                    try:
                        data, addr = sock.recvfrom(1024)
                        self._parse_search_response(data, addr[0])
                    except TimeoutError:
                        pass  # No resend - OT safety
                    except Exception as e:
                        logger.debug(f"KNX recv error: {e}")

                logger.info(f"KNX found {len(self.discovered_devices)} devices")
            finally:
                sock.close()

        except Exception as e:
            logger.error(f"KNX discovery error: {e}")

        return self.discovered_devices

    def _parse_search_response(self, data: bytes, ip: str) -> None:
        """Parse KNXnet/IP SearchResponse"""
        try:
            if len(data) < 14:
                return

            # Parse header
            header_len, version, service_type, total_len = struct.unpack(">BBHH", data[:6])

            if service_type != 0x0202:  # SEARCH_RESPONSE
                return

            # Skip to DIB (Device Information Block)
            offset = 6

            # Skip control endpoint HPAI (8 bytes)
            if offset + 8 > len(data):
                return
            offset += 8

            # Parse DIB Device Info
            if offset + 2 > len(data):
                return

            dib_len = data[offset]
            dib_type = data[offset + 1]

            if dib_type == 0x01 and dib_len >= 54:  # DEVICE_INFO
                # Parse device info
                # Medium (1), Status (1), Individual Address (2), Project ID (2)
                # Serial (6), Multicast (4), MAC (6), Name (30)
                #
                # dib_len is the value CLAIMED by the response; it is not proof
                # that the datagram actually carries that many bytes (a
                # truncated/short SearchResponse still passes the >= 54 check
                # above). Every deeper field read below is bounds-checked
                # against the real buffer so a truncated DIB still yields a
                # device record with whatever fields fit, instead of raising
                # IndexError/struct.error into the catch-all and silently
                # dropping the device.

                medium = data[offset + 2] if offset + 2 < len(data) else 0
                status = data[offset + 3] if offset + 3 < len(data) else 0

                if offset + 6 <= len(data):
                    individual_addr = struct.unpack(">H", data[offset + 4 : offset + 6])[0]
                    # Extract individual address parts
                    area = (individual_addr >> 12) & 0x0F
                    line = (individual_addr >> 8) & 0x0F
                    device_num = individual_addr & 0xFF
                    knx_addr = f"{area}.{line}.{device_num}"
                else:
                    knx_addr = ""

                # MAC address (offset + 24)
                mac_offset = offset + 24
                if mac_offset + 6 <= len(data):
                    mac = ":".join(f"{b:02x}" for b in data[mac_offset : mac_offset + 6])
                else:
                    mac = ""

                # Device name (offset + 30, 30 bytes max)
                name_offset = offset + 30
                name = ""
                if name_offset < len(data):
                    name_end = min(name_offset + 30, len(data))
                    name = (
                        data[name_offset:name_end].decode("ascii", errors="ignore").rstrip("\x00")
                    )

                knx_data = {
                    "individual_address": knx_addr,
                    "medium": self._get_medium_type(medium),
                    "status": status,
                    "programming_mode": bool(status & 0x01),
                }

                with self._lock:
                    key = mac if mac else ip
                    if key not in self.discovered_devices:
                        device = DiscoveredDevice(
                            mac_address=mac,
                            ip_addresses=[ip],
                            name=name,
                            device_type="KNX Device",
                            discovered_by=["knx"],
                            first_seen=datetime.now().isoformat(),
                            last_seen=datetime.now().isoformat(),
                            knx_data=knx_data,
                        )
                        self.discovered_devices[key] = device
                    else:
                        self.discovered_devices[key].knx_data = knx_data
                        self.discovered_devices[key].last_seen = datetime.now().isoformat()

        except Exception as e:
            logger.debug(f"Error parsing KNX response from {ip}: {e}")

    def _get_medium_type(self, medium: int) -> str:
        """Get KNX medium type string"""
        media = {
            0x01: "TP (Twisted Pair)",
            0x02: "PL (Powerline)",
            0x04: "RF (Radio Frequency)",
            0x20: "IP",
        }
        return media.get(medium, f"Unknown ({medium})")


class BACnetScanner:
    """BACnet device discovery via Who-Is broadcast

    BACnet uses UDP port 47808 (0xBAC0) for broadcast discovery.
    Sends Who-Is and listens for I-Am responses.
    """

    BACNET_PORT = 47808

    def __init__(self, interface: str, subnet: Optional[str] = None, timeout: int = 10):
        self.interface = validate_interface(interface)
        self.subnet = validate_subnet(subnet)
        self.timeout = validate_timeout(timeout)
        self.discovered_devices: Dict[str, DiscoveredDevice] = {}
        self._lock = threading.Lock()

    def scan(self) -> Dict[str, DiscoveredDevice]:
        """Send BACnet Who-Is and collect I-Am responses"""
        try:
            sock = create_udp_socket(self.interface, timeout=2.0, broadcast=True)
            try:
                # Build BACnet Who-Is
                # BVLC header: type (1), function (1), length (2)
                # 0x81 = BACnet/IP, 0x0b = Original-Broadcast-NPDU
                bvlc = struct.pack(">BBH", 0x81, 0x0B, 0)

                # NPDU: version (1), control (1)
                # 0x01 = version, 0x04 = expecting reply, no DNET/SNET
                npdu = struct.pack(">BB", 0x01, 0x04)

                # APDU: Who-Is (unconfirmed request)
                # PDU type (0x10 = unconfirmed), service choice (0x08 = Who-Is)
                apdu = struct.pack(">BB", 0x10, 0x08)

                # Update BVLC length
                packet = bvlc[:2] + struct.pack(">H", 4 + len(npdu) + len(apdu)) + npdu + apdu

                # Send to all broadcast addresses to reach devices on different subnets
                broadcast_addrs = get_all_broadcast_addresses(self.interface, self.subnet)
                for i, broadcast_addr in enumerate(broadcast_addrs):
                    sendto(sock, packet, (broadcast_addr, self.BACNET_PORT))
                    logger.debug(f"BACnet: Sent Who-Is to {broadcast_addr}:{self.BACNET_PORT}")
                    # Small delay between broadcasts to avoid packet bursts
                    if i < len(broadcast_addrs) - 1:
                        time.sleep(0.1)

                # Collect responses (single send only - no resend to avoid OT disruption)
                start_time = time.time()
                while time.time() - start_time < self.timeout:
                    try:
                        data, addr = sock.recvfrom(1500)
                        self._parse_i_am_response(data, addr[0])
                    except TimeoutError:
                        pass  # No resend - OT safety
                    except Exception as e:
                        logger.debug(f"BACnet recv error: {e}")

                logger.info(f"BACnet found {len(self.discovered_devices)} devices")
            finally:
                sock.close()

        except Exception as e:
            logger.error(f"BACnet discovery error: {e}")

        return self.discovered_devices

    def _parse_i_am_response(self, data: bytes, ip: str) -> None:
        """Parse BACnet I-Am response"""
        try:
            if len(data) < 12:
                return

            # Parse BVLC header
            bvlc_type, bvlc_func, bvlc_len = struct.unpack(">BBH", data[:4])

            if bvlc_type != 0x81:  # Not BACnet/IP
                return

            offset = 4

            # Parse NPDU (data[offset] is the version byte, unused)
            npdu_control = data[offset + 1]
            offset += 2

            # Skip DNET/DADR if present
            dnet_present = bool(npdu_control & 0x20)
            if dnet_present:
                dlen = data[offset + 2] if offset + 2 < len(data) else 0
                offset += 3 + dlen  # DNET (2) + DLEN (1) + DADR (dlen)

            # Skip SNET/SADR if present
            if npdu_control & 0x08:  # SNET present
                slen = data[offset + 2] if offset + 2 < len(data) else 0
                offset += 3 + slen  # SNET (2) + SLEN (1) + SADR (slen)

            # Hop count trails the source fields (clause 6.2.2 orders the NPCI as
            # DNET, DLEN, DADR, SNET, SLEN, SADR, Hop Count) and is only present
            # when DNET is. Skipping it before SNET would misread SLEN as SADR[0].
            if dnet_present:
                offset += 1

            if offset >= len(data):
                return

            # Parse APDU
            pdu_type = data[offset] >> 4
            if pdu_type != 1:  # Not unconfirmed request
                return

            service_choice = data[offset + 1] if offset + 1 < len(data) else 0
            if service_choice != 0x00:  # Not I-Am
                return

            offset += 2

            # Parse I-Am content.
            # I-Am-Request (ASHRAE 135 clause 21) carries its four parameters as
            # APPLICATION-tagged primitives, not context-tagged ones:
            #   app tag 12 -> BACnetObjectIdentifier (4 octets)
            #   app tag 2  -> Unsigned: 1st occurrence maxAPDULengthAccepted,
            #                 2nd occurrence vendorID
            #   app tag 9  -> Enumerated segmentationSupported
            # A real I-Am APDU looks like:
            #   10 00 C4 02 00 00 03 22 01 E0 91 00 21 4B
            # The context-tag branches are kept as a fallback for senders that
            # encode the parameters non-conformantly.

            device_instance = 0
            vendor_id = 0
            max_apdu = 0
            unsigned_seen = 0

            while offset < len(data):
                tag = data[offset]
                tag_class = (tag >> 3) & 0x01
                tag_number = tag >> 4
                length = tag & 0x07

                offset += 1

                if tag_number == 0x0F and offset < len(data):
                    # Tag number 15 means the real tag number is in the next octet
                    tag_number = data[offset]
                    offset += 1

                if length in (6, 7):
                    # Opening/closing tag - carries no content octets
                    length = 0
                elif length == 5 and offset < len(data):
                    length = data[offset]
                    offset += 1

                if offset + length > len(data):
                    break

                value = data[offset : offset + length]

                if tag_class == 1:  # context-specific (fallback)
                    if tag_number == 0 and length >= 4:
                        device_instance = struct.unpack(">I", value[:4])[0] & 0x3FFFFF
                    elif tag_number == 1 and length >= 1:
                        max_apdu = int.from_bytes(value, "big")
                    elif tag_number == 3 and length >= 1:
                        vendor_id = int.from_bytes(value, "big")
                elif tag_number == 12 and length >= 4:  # BACnetObjectIdentifier
                    device_instance = struct.unpack(">I", value[:4])[0] & 0x3FFFFF
                elif tag_number == 2 and length >= 1:  # Unsigned
                    unsigned_seen += 1
                    if unsigned_seen == 1:
                        max_apdu = int.from_bytes(value, "big")
                    elif unsigned_seen == 2:
                        vendor_id = int.from_bytes(value, "big")

                offset += length

            bacnet_data = {
                "device_instance": device_instance,
                "vendor_id": vendor_id,
                "vendor_name": self._get_vendor_name(vendor_id),
                "max_apdu": max_apdu,
            }

            with self._lock:
                if ip not in self.discovered_devices:
                    device = DiscoveredDevice(
                        ip_addresses=[ip],
                        name=f"BACnet Device {device_instance}",
                        manufacturer=bacnet_data["vendor_name"],
                        device_type="BACnet Device",
                        discovered_by=["bacnet"],
                        first_seen=datetime.now().isoformat(),
                        last_seen=datetime.now().isoformat(),
                        bacnet_data=bacnet_data,
                    )
                    self.discovered_devices[ip] = device
                else:
                    self.discovered_devices[ip].bacnet_data = bacnet_data
                    self.discovered_devices[ip].last_seen = datetime.now().isoformat()

        except Exception as e:
            logger.debug(f"Error parsing BACnet I-Am from {ip}: {e}")

    def _get_vendor_name(self, vendor_id: int) -> str:
        """Get BACnet vendor name from ID"""
        vendors = {
            0: "ASHRAE",
            2: "The Trane Company",
            5: "Johnson Controls",
            7: "Siemens",
            15: "Honeywell",
            24: "Carrier",
            26: "Schneider Electric",
            95: "Distech Controls",
            105: "Phoenix Contact",
            260: "KMC Controls",
            343: "Beckhoff",
        }
        return vendors.get(vendor_id, f"Vendor {vendor_id}")


class EtherNetIPScanner:
    """EtherNet/IP device discovery via List Identity broadcast.

    Uses the standalone broadcast_discovery function from the ethernetip module.
    """

    def __init__(
        self,
        interface: str,
        subnet: Optional[str] = None,
        timeout: int = 10,
    ):
        self.interface = validate_interface(interface)
        self.subnet = validate_subnet(subnet)
        self.timeout = validate_timeout(timeout)
        self.discovered_devices: Dict[str, DiscoveredDevice] = {}
        self._lock = threading.Lock()

    def scan(self) -> Dict[str, DiscoveredDevice]:
        """Send List Identity broadcast and collect responses."""
        if not _ethernetip.is_available:
            logger.warning("EtherNet/IP: ethernetip module not available")
            return self.discovered_devices
        try:
            broadcast_discovery = _ethernetip().broadcast_discovery

            # Get local IP for the interface
            lhost = get_interface_ip(self.interface)
            if not lhost:
                logger.debug(f"EtherNet/IP: Could not get IP for {self.interface}")
                return self.discovered_devices

            logger.debug(f"EtherNet/IP: Broadcasting from {lhost} (subnet: {self.subnet})")

            # Call the standalone broadcast function
            devices = broadcast_discovery(
                lhost=lhost,
                subnet=self.subnet,
                timeout=float(self.timeout),
            )

            # Convert results to DiscoveredDevice objects
            for dev in devices:
                ip = dev.get("ip_address", "")
                if not ip:
                    continue

                revision = dev.get("revision", (0, 0))
                if isinstance(revision, tuple):
                    revision_str = f"{revision[0]}.{revision[1]}"
                else:
                    revision_str = str(revision)

                device_info = DiscoveredDevice(
                    ip_addresses=[ip],
                    name=dev.get("product_name") or f"EtherNet/IP Device ({ip})",
                    manufacturer=dev.get("vendor_name", "Unknown"),
                    model=f"Product Code {dev.get('product_code', 0)}",
                    device_type=dev.get("device_type_name", "EtherNet/IP Device"),
                    discovered_by=["ethernetip"],
                    first_seen=datetime.now().isoformat(),
                    last_seen=datetime.now().isoformat(),
                    ethernetip_data={
                        "vendor_id": dev.get("vendor_id", 0),
                        "vendor_name": dev.get("vendor_name", "Unknown"),
                        "device_type": dev.get("device_type", 0),
                        "device_type_name": dev.get("device_type_name", "Unknown"),
                        "product_code": dev.get("product_code", 0),
                        "revision": revision_str,
                        "serial_number": dev.get("serial_number", 0),
                        "product_name": dev.get("product_name", ""),
                        "status": dev.get("status", 0),
                        "state": dev.get("state", 0),
                        "state_name": dev.get("state_name", "Unknown"),
                    },
                )

                with self._lock:
                    self.discovered_devices[ip] = device_info
                    logger.debug(
                        f"EtherNet/IP: Found {ip} - {device_info.manufacturer} {device_info.name}"
                    )

        except Exception as e:
            logger.warning(f"EtherNet/IP discovery failed: {e}")

        return self.discovered_devices


class CODESYSScanner:
    """CODESYS V3 device discovery via UDP broadcast.

    CODESYS V3 uses UDP ports 1740-1743 for device discovery.
    Sends Network Service Request and listens for responses.
    """

    UDP_PORTS = [1740, 1741, 1742, 1743]
    MAGIC = 0xC5
    SERVICE_NETWORK_REQ = 0x03
    SERVICE_NETWORK_RES = 0x04

    # Address suffix for discovery packets (per reference implementation)
    ADDRESS_SUFFIX = b"\x80\x00\x00\x00"

    def __init__(
        self,
        interface: str,
        subnet: Optional[str] = None,
        timeout: int = 10,
    ):
        self.interface = validate_interface(interface)
        self.subnet = validate_subnet(subnet)
        self.timeout = validate_timeout(timeout)
        self.discovered_devices: Dict[str, DiscoveredDevice] = {}
        self._lock = threading.Lock()

    def scan(self) -> Dict[str, DiscoveredDevice]:
        """Send CODESYS V3 discovery broadcast and collect responses"""
        try:
            # Build discovery packet
            packet = self._build_discovery_packet()

            sock = create_udp_socket(self.interface, timeout=0.5, broadcast=True)
            try:
                # Get all broadcast addresses to reach devices on different subnets
                broadcast_addrs = get_all_broadcast_addresses(self.interface, self.subnet)

                # Send to all CODESYS UDP ports on all broadcast addresses (with delay for OT safety)
                for broadcast_addr in broadcast_addrs:
                    for i, port in enumerate(self.UDP_PORTS):
                        try:
                            sendto(sock, packet, (broadcast_addr, port))
                            logger.debug(f"CODESYS: Sent discovery to {broadcast_addr}:{port}")
                            # 200ms delay between sends to avoid packet bursts on OT networks
                            time.sleep(0.2)
                        except Exception as e:
                            logger.debug(f"CODESYS: Failed to send to {broadcast_addr}:{port}: {e}")

                # Collect responses
                start_time = time.time()
                seen_ips: Set[str] = set()

                while time.time() - start_time < self.timeout:
                    try:
                        data, addr = sock.recvfrom(4096)
                        ip = addr[0]
                        port = addr[1]

                        if ip in seen_ips:
                            continue

                        # Parse response
                        device_info = self._parse_discovery_response(data, ip, port)
                        if device_info:
                            seen_ips.add(ip)
                            with self._lock:
                                self.discovered_devices[ip] = device_info
                                logger.debug(f"CODESYS: Found {ip}:{port} - {device_info.name}")

                    except TimeoutError:
                        continue
                    except Exception as e:
                        logger.debug(f"CODESYS receive error: {e}")

                logger.info(f"CODESYS found {len(self.discovered_devices)} devices")
            finally:
                sock.close()

        except Exception as e:
            logger.warning(f"CODESYS discovery failed: {e}")

        return self.discovered_devices

    def _build_discovery_packet(self) -> bytes:
        """Build CODESYS V3 UDP discovery packet."""
        # Get local IP last octet for relative addressing. CODESYS is a LAN
        # protocol so use the broadcast address (which the discovery socket is
        # already bound to) as the route target instead of an external IP.
        from oida.utils.socket_helpers import get_local_ip

        src_ip_octet = 1
        local_ip, err = get_local_ip("255.255.255.255", fallback="0.0.0.0")
        if err is None:
            try:
                src_ip_octet = int(local_ip.split(".")[-1])
            except (ValueError, IndexError) as e:
                logger.debug(f"CODESYS: Could not parse local IP {local_ip}: {e}")
        else:
            logger.debug(f"CODESYS: Could not determine local IP: {err}")

        # PDU header (6 bytes) - fixed values from reference implementation
        hop_info = 0x74  # hop_count=14, header_len=4
        packet_info = 0x50  # priority=1, signal=0, addr_type=1 (relative), blk_len=0
        header = struct.pack(
            ">BBBBBB",
            self.MAGIC,
            hop_info,
            packet_info,
            self.SERVICE_NETWORK_REQ,
            0x00,  # message ID
            0x30,  # lengths: recv_len=3, send_len=0
        )

        # Relative address (4 bytes) + suffix (4 bytes)
        address = struct.pack(
            "BBBB",
            0x00,  # src port index (0 = 1740)
            src_ip_octet & 0xFF,
            0x00,  # dst port index
            0xFF,  # broadcast indicator
        )
        address = address + self.ADDRESS_SUFFIX  # Total 8 bytes

        # Discovery command (sub_command + version + message_id)
        command = struct.pack(
            "<HHI",
            0xC202,  # sub_command
            0x0103,  # version (259)
            0x03354024,  # message_id
        )

        return header + address + command

    def _parse_discovery_response(
        self, data: bytes, ip: str, port: int
    ) -> Optional[DiscoveredDevice]:
        """Parse CODESYS V3 discovery response."""
        try:
            if len(data) < 10:
                return None

            # Check magic byte
            if data[0] != self.MAGIC:
                return None

            # Check service ID (should be RES_NETWORK = 0x04)
            if len(data) > 3 and data[3] != self.SERVICE_NETWORK_RES:
                return None

            # Parse header
            packet_info = data[2]
            addr_type = (packet_info >> 4) & 0x01

            # Skip header (6 bytes) + address (4 relative or 12 full)
            offset = 6 + (4 if addr_type == 1 else 12)

            if len(data) <= offset + 2:
                return None

            # Parse NSClientHandleData version
            data_version = struct.unpack_from("<H", data, offset)[0]
            offset += 2

            # Parse device info using structured format
            device_name = ""
            vendor = ""
            node_name = ""
            version = ""
            max_channels = 0
            target_type = 0
            serial_number = ""

            # Structured header: the block below consumes
            # 4 + 2 + 4 + 2 + 2 + 2 + 4 + 4 + 4 = 28 bytes before the strings.
            # Guarding on 24 let a 24-27 byte header through, which then raised
            # struct.error on the final target_version unpack and was swallowed
            # by the broad handler below, silently dropping the whole response.
            if len(data) < offset + 28:
                return None

            # Parse header fields
            struct.unpack_from("<I", data, offset)[0]
            offset += 4

            max_channels = struct.unpack_from("<H", data, offset)[0]
            offset += 2

            struct.unpack_from("<I", data, offset)[0]
            offset += 4

            # String lengths (in UTF-16 character counts)
            node_name_length = struct.unpack_from("<H", data, offset)[0]
            offset += 2

            device_name_length = struct.unpack_from("<H", data, offset)[0]
            offset += 2

            vendor_name_length = struct.unpack_from("<H", data, offset)[0]
            offset += 2

            target_type = struct.unpack_from("<I", data, offset)[0]
            offset += 4

            struct.unpack_from("<I", data, offset)[0]
            offset += 4

            # Version as single 32-bit int with bit shifts
            target_version = struct.unpack_from("<I", data, offset)[0]
            offset += 4

            major = (target_version >> 24) & 0xFF
            minor = (target_version >> 16) & 0xFF
            build = (target_version >> 8) & 0xFF
            revision = target_version & 0xFF
            version = f"{major}.{minor}.{build}.{revision}"

            # Handle version 1024 (0x0400) extra fields
            serial_len = 0
            if data_version == 1024:
                if len(data) >= offset + 12:
                    offset += 4  # unknown2
                    serial_len = struct.unpack_from("<H", data, offset)[0]
                    offset += 2
                    padding_len = struct.unpack_from("<I", data, offset)[0]
                    offset += 4
                    offset += padding_len  # skip padding
                    offset += 2  # unknown3+unknown4

            # Parse UTF-16-LE strings with explicit lengths
            if node_name_length > 0 and len(data) >= offset + node_name_length * 2:
                node_name = data[offset : offset + node_name_length * 2].decode(
                    "utf-16-le", errors="replace"
                )
                offset += node_name_length * 2 + 2  # +2 for separator

            if device_name_length > 0 and len(data) >= offset + device_name_length * 2:
                raw_name = data[offset : offset + device_name_length * 2].decode(
                    "utf-16-le", errors="replace"
                )
                # Strip common prefixes
                for prefix in ["CODESYS Control for ", "CODESYS Control ", "CODESYS "]:
                    if raw_name.startswith(prefix):
                        raw_name = raw_name[len(prefix) :]
                        break
                device_name = raw_name.strip()
                offset += device_name_length * 2 + 2

            if vendor_name_length > 0 and len(data) >= offset + vendor_name_length * 2:
                vendor = data[offset : offset + vendor_name_length * 2].decode(
                    "utf-16-le", errors="replace"
                )
                offset += vendor_name_length * 2 + 2

            # Serial number for version 1024
            if data_version == 1024 and serial_len > 0 and len(data) >= offset + serial_len:
                serial_number = data[offset : offset + serial_len].decode("utf-8", errors="replace")

            codesys_data = {
                "protocol_version": "V3",
                "device_name": device_name,
                "vendor": vendor,
                "node_name": node_name,
                "version": version,
                "max_channels": max_channels,
                "target_type": target_type,
                "data_version": data_version,
                "serial_number": serial_number,
                "port": port,
            }

            return DiscoveredDevice(
                ip_addresses=[ip],
                name=device_name or node_name or f"CODESYS Device ({ip})",
                manufacturer=vendor or "CODESYS",
                model=device_name,
                device_type="CODESYS PLC",
                description=f"CODESYS V3 {version}" if version else "CODESYS V3",
                discovered_by=["codesys"],
                first_seen=datetime.now().isoformat(),
                last_seen=datetime.now().isoformat(),
                codesys_data=codesys_data,
            )

        except Exception as e:
            logger.debug(f"CODESYS parse error for {ip}: {e}")
            return None


class ADSScanner:
    """Beckhoff ADS/TwinCAT device discovery via UDP broadcast.

    Uses UDP port 48899 with Beckhoff discovery protocol:
    - Magic: 0x71146603 (little-endian)
    - Service 1: Identify (query device info)
    - TLV response format for device details
    """

    ADS_UDP_PORT = 48899
    ADS_UDP_MAGIC = 0x71146603  # Beckhoff UDP protocol signature (LE: 03 66 14 71)
    ADS_UDP_SVC_IDENTIFY = 1  # Query remote system info

    # TLV tag types from ADS protocol
    ADS_UDP_TAG = {
        "STATUS": 1,
        "PASSWORD": 2,
        "TC_VERSION": 3,
        "OS_VERSION": 4,
        "HOSTNAME": 5,
        "NETID": 7,
        "OPTIONS": 9,
        "ROUTE_NAME": 12,
        "USERNAME": 13,
        "FINGERPRINT": 18,
    }

    def __init__(
        self,
        interface: str,
        subnet: Optional[str] = None,
        timeout: int = 10,
    ):
        self.interface = validate_interface(interface)
        self.subnet = validate_subnet(subnet)
        self.timeout = validate_timeout(timeout)
        self.discovered_devices: Dict[str, DiscoveredDevice] = {}
        self._lock = threading.Lock()

    def scan(self) -> Dict[str, DiscoveredDevice]:
        """Send ADS UDP discovery broadcast and collect responses."""
        try:
            sock = create_udp_socket(self.interface, timeout=2.0, broadcast=True)

            # Build discovery request (Identify service)
            # Format: magic(4) + invoke_id(4) + operation(4) + reserved(16) = 28 bytes
            invoke_id = 0x00000001
            operation = self.ADS_UDP_SVC_IDENTIFY
            request = struct.pack("<III", self.ADS_UDP_MAGIC, invoke_id, operation) + b"\x00" * 16

            # Send to all broadcast addresses to reach devices on different subnets
            broadcast_addrs = get_all_broadcast_addresses(self.interface, self.subnet)
            for i, broadcast_addr in enumerate(broadcast_addrs):
                sendto(sock, request, (broadcast_addr, self.ADS_UDP_PORT))
                logger.debug(f"ADS: Sent discovery to {broadcast_addr}:{self.ADS_UDP_PORT}")
                # Small delay between broadcasts
                if i < len(broadcast_addrs) - 1:
                    time.sleep(0.1)

            # Collect responses
            start_time = time.time()
            seen_ips: Set[str] = set()

            while time.time() - start_time < self.timeout:
                try:
                    data, addr = sock.recvfrom(1024)
                    ip = addr[0]

                    if ip in seen_ips:
                        continue

                    device_info = self._parse_discovery_response(data, ip)
                    if device_info:
                        seen_ips.add(ip)
                        with self._lock:
                            self.discovered_devices[ip] = device_info
                            logger.debug(f"ADS: Found {ip} - {device_info.name}")

                except TimeoutError:
                    continue
                except Exception as e:
                    logger.debug(f"ADS receive error: {e}")

            sock.close()
            logger.info(f"ADS found {len(self.discovered_devices)} devices")

        except Exception as e:
            logger.warning(f"ADS discovery failed: {e}")

        return self.discovered_devices

    def _parse_discovery_response(self, data: bytes, ip: str) -> Optional[DiscoveredDevice]:
        """Parse ADS UDP discovery response."""
        try:
            if len(data) < 12:
                return None

            # Validate magic
            magic, resp_invoke, resp_op = struct.unpack("<III", data[:12])
            if magic != self.ADS_UDP_MAGIC:
                return None

            # Parse TLV data after 12-byte header
            device_data = self._parse_tlv_tags(data[12:])

            hostname = device_data.get("hostname", "")
            netid = device_data.get("netid", "")
            tc_version = device_data.get("tc_version", "")
            os_version = device_data.get("os_version", "")

            ads_data = {
                "hostname": hostname,
                "netid": netid,
                "tc_version": tc_version,
                "os_version": os_version,
                "fingerprint": device_data.get("fingerprint", ""),
            }

            return DiscoveredDevice(
                ip_addresses=[ip],
                name=hostname or f"TwinCAT Device ({ip})",
                manufacturer="Beckhoff",
                model="TwinCAT",
                device_type="Beckhoff ADS/TwinCAT",
                description=f"TwinCAT {tc_version}" if tc_version else "TwinCAT PLC",
                discovered_by=["ads"],
                first_seen=datetime.now().isoformat(),
                last_seen=datetime.now().isoformat(),
                ads_data=ads_data,
            )

        except Exception as e:
            logger.debug(f"ADS parse error for {ip}: {e}")
            return None

    def _parse_tlv_tags(self, data: bytes) -> Dict[str, Any]:
        """Parse TLV tags from ADS UDP discovery response."""
        result: Dict[str, Any] = {}
        pos = 0

        while pos + 4 <= len(data):
            try:
                tag_type, tag_len = struct.unpack("<HH", data[pos : pos + 4])
                pos += 4

                if tag_len == 0 or pos + tag_len > len(data):
                    break

                tag_data = data[pos : pos + tag_len]
                pos += tag_len

                if tag_type == self.ADS_UDP_TAG["HOSTNAME"]:
                    result["hostname"] = tag_data.rstrip(b"\x00").decode("utf-8", errors="ignore")
                elif tag_type == self.ADS_UDP_TAG["NETID"]:
                    if len(tag_data) >= 6:
                        result["netid"] = ".".join(str(b) for b in tag_data[:6])
                elif tag_type == self.ADS_UDP_TAG["TC_VERSION"]:
                    if len(tag_data) >= 4:
                        result["tc_version"] = (
                            f"{tag_data[0]}.{tag_data[1]}.{struct.unpack('<H', tag_data[2:4])[0]}"
                        )
                elif tag_type == self.ADS_UDP_TAG["OS_VERSION"]:
                    result["os_version"] = tag_data.rstrip(b"\x00").decode("utf-8", errors="ignore")
                elif tag_type == self.ADS_UDP_TAG["FINGERPRINT"]:
                    result["fingerprint"] = tag_data.hex()

            except Exception:
                break

        return result
