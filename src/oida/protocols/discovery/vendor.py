"""
Vendor-specific device discovery scanners.

Contains:
- MoxaScanner: Moxa serial device server discovery (UDP 4800)
- LantronixScanner: Lantronix serial device server discovery (UDP 30718)
"""

import socket
import threading
import time
from datetime import datetime
from typing import Dict, Optional, Set

from .core import (
    DiscoveredDevice,
    create_udp_socket,
    get_all_broadcast_addresses,
    validate_interface,
    validate_timeout,
    validate_subnet,
)
from ...utils.rate_limiter import sendto
from ...utils.ics_logger import get_module_logger

logger = get_module_logger(__name__)


class MoxaScanner:
    """Moxa UDP Device Discovery (port 4800).

    Moxa serial device servers (NPort, OnCell, MGate) respond to
    UDP broadcast probes with device information.

    Protocol:
    - Request: 8 bytes starting with 0x01 (function code)
    - Response: 24 bytes starting with 0x81, contains MAC at bytes 13-18

    References:
    - Metasploit: auxiliary/scanner/scada/moxa_discover
    - CVE-2016-9361: Information disclosure in older firmware
    """

    MOXA_PORT = 4800
    MOXA_OUI = bytes.fromhex("0090e8")
    # Function code 0x01 = discovery/identify, byte 4 = payload length (8)
    DISCOVERY_PROBE = b"\x01\x00\x00\x08\x00\x00\x00\x00"

    def __init__(
        self,
        interface: str,
        subnet: Optional[str] = None,
        timeout: float = 5.0,
    ):
        self.interface = validate_interface(interface)
        self.subnet = validate_subnet(subnet)
        self.timeout = validate_timeout(timeout)
        self.discovered_devices: Dict[str, DiscoveredDevice] = {}
        self._lock = threading.Lock()

    def scan(self) -> Dict[str, DiscoveredDevice]:
        """Send Moxa discovery broadcast and collect responses."""
        sock = None
        try:
            sock = create_udp_socket(self.interface, timeout=0.5, broadcast=True)

            # Send discovery probe to all broadcast addresses
            broadcast_addrs = get_all_broadcast_addresses(self.interface, self.subnet)
            for i, broadcast_addr in enumerate(broadcast_addrs):
                sendto(sock, self.DISCOVERY_PROBE, (broadcast_addr, self.MOXA_PORT))
                logger.debug(f"Moxa: Sent discovery to {broadcast_addr}:{self.MOXA_PORT}")
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

                    device = self._parse_response(data, ip)
                    if device:
                        seen_ips.add(ip)
                        with self._lock:
                            self.discovered_devices[ip] = device
                            logger.debug(f"Moxa: Found device at {ip}")

                except TimeoutError:
                    continue
                except OSError as e:
                    logger.debug(f"Moxa socket error: {e}")

            logger.info(f"Moxa found {len(self.discovered_devices)} devices")

        except OSError as e:
            logger.warning(f"Moxa discovery socket error: {e}")
        except Exception as e:
            logger.warning(f"Moxa discovery failed: {e}")
        finally:
            if sock:
                try:
                    sock.close()
                except OSError as e:
                    logger.debug(f"sock.close(): {e}")

        return self.discovered_devices

    def scan_host(self, host: str) -> Optional[DiscoveredDevice]:
        """Send discovery probe to specific host."""
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            sendto(sock, self.DISCOVERY_PROBE, (host, self.MOXA_PORT))
            data, addr = sock.recvfrom(1024)
            return self._parse_response(data, addr[0])
        except TimeoutError as e:
            logger.debug(f"Moxa discovery probe timed out for {host}: {e}")
            return None
        except OSError as e:
            logger.debug(f"Moxa scan_host socket error for {host}: {e}")
            return None
        finally:
            if sock:
                try:
                    sock.close()
                except OSError as e:
                    logger.debug(f"sock.close(): {e}")

    def _parse_response(self, data: bytes, ip: str) -> Optional[DiscoveredDevice]:
        """Parse Moxa discovery response.

        Valid response:
        - 24 bytes minimum
        - First byte: 0x81 (response function code = request 0x01 | 0x80)
        - Bytes 13-15: Moxa OUI (00:90:E8)
        - Bytes 13-18: Full MAC address
        """
        if len(data) < 24:
            logger.debug(f"Moxa: Response too short from {ip}: {len(data)} bytes")
            return None

        # Check response function code (request code 0x01 + 0x80)
        if data[0] != 0x81:
            logger.debug(f"Moxa: Invalid function code from {ip}: 0x{data[0]:02x}")
            return None

        # Verify Moxa OUI at bytes 13-15 (0-indexed)
        if len(data) >= 16 and data[13:16] != self.MOXA_OUI:
            logger.debug(f"Moxa: OUI mismatch from {ip}: {data[13:16].hex()}")
            return None

        # Extract MAC address (bytes 13-18)
        mac = ":".join(f"{b:02x}" for b in data[13:19])

        # Build device info
        moxa_data = {
            "function_code": data[0],
            "raw_response": data.hex(),
            "mac_address": mac,
        }

        return DiscoveredDevice(
            mac_address=mac,
            ip_addresses=[ip],
            name=f"Moxa Device ({ip})",
            manufacturer="Moxa",
            device_type="Serial Device Server",
            description="Moxa NPort/OnCell/MGate",
            discovered_by=["moxa"],
            first_seen=datetime.now().isoformat(),
            last_seen=datetime.now().isoformat(),
            moxa_data=moxa_data,
        )


class LantronixScanner:
    """Lantronix UDP Device Discovery (port 30718).

    Lantronix serial device servers (XPort, UDS, EDS) respond to
    UDP broadcast probes with device status information.

    Protocol:
    - Request: 4 bytes (0x00 0x00 0x00 0xF6)
    - Response: 30 bytes with device status

    References:
    - Lantronix Wiki: http://wiki.lantronix.com/wiki/Lantronix_Discovery_Protocol
    """

    LANTRONIX_PORT = 30718  # 0x77FE
    DISCOVERY_PROBE = b"\x00\x00\x00\xf6"

    def __init__(
        self,
        interface: str,
        subnet: Optional[str] = None,
        timeout: float = 5.0,
    ):
        self.interface = validate_interface(interface)
        self.subnet = validate_subnet(subnet)
        self.timeout = validate_timeout(timeout)
        self.discovered_devices: Dict[str, DiscoveredDevice] = {}
        self._lock = threading.Lock()

    def scan(self) -> Dict[str, DiscoveredDevice]:
        """Send Lantronix discovery broadcast and collect responses."""
        sock = None
        try:
            sock = create_udp_socket(self.interface, timeout=0.5, broadcast=True)

            # Send discovery probe to all broadcast addresses
            broadcast_addrs = get_all_broadcast_addresses(self.interface, self.subnet)
            for i, broadcast_addr in enumerate(broadcast_addrs):
                sendto(sock, self.DISCOVERY_PROBE, (broadcast_addr, self.LANTRONIX_PORT))
                logger.debug(f"Lantronix: Sent discovery to {broadcast_addr}:{self.LANTRONIX_PORT}")
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

                    device = self._parse_response(data, ip)
                    if device:
                        seen_ips.add(ip)
                        with self._lock:
                            self.discovered_devices[ip] = device
                            logger.debug(f"Lantronix: Found device at {ip}")

                except TimeoutError:
                    continue
                except OSError as e:
                    logger.debug(f"Lantronix receive error: {e}")

            logger.info(f"Lantronix found {len(self.discovered_devices)} devices")

        except OSError as e:
            logger.warning(f"Lantronix discovery socket error: {e}")
        except Exception as e:
            logger.warning(f"Lantronix discovery failed: {e}")
        finally:
            if sock:
                try:
                    sock.close()
                except OSError as e:
                    logger.debug(f"sock.close(): {e}")

        return self.discovered_devices

    def scan_host(self, host: str) -> Optional[DiscoveredDevice]:
        """Send discovery probe to specific host."""
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            sendto(sock, self.DISCOVERY_PROBE, (host, self.LANTRONIX_PORT))
            data, addr = sock.recvfrom(1024)
            return self._parse_response(data, addr[0])
        except TimeoutError as e:
            logger.debug(f"Lantronix discovery probe timed out for {host}: {e}")
            return None
        except OSError as e:
            logger.debug(f"Lantronix scan_host socket error for {host}: {e}")
            return None
        finally:
            if sock:
                try:
                    sock.close()
                except OSError as e:
                    logger.debug(f"sock.close(): {e}")

    def _parse_response(self, data: bytes, ip: str) -> Optional[DiscoveredDevice]:
        """Parse Lantronix discovery response.

        Response format (30 bytes):
        - Bytes 0-5: MAC address
        - Bytes 6-9: IP address
        - Bytes 10-13: Subnet mask
        - Bytes 14-17: Gateway
        - Remaining: Device-specific status
        """
        if len(data) < 30:
            logger.debug(f"Lantronix: Response too short from {ip}: {len(data)} bytes")
            return None

        # Extract MAC address from bytes 0-5
        mac = ":".join(f"{b:02x}" for b in data[0:6])

        # Extract configured IP (may differ from source IP)
        config_ip = socket.inet_ntoa(data[6:10])

        # Extract subnet mask
        subnet_mask = socket.inet_ntoa(data[10:14])

        # Extract gateway
        gateway = socket.inet_ntoa(data[14:18])

        # Build device info
        lantronix_data = {
            "mac_address": mac,
            "configured_ip": config_ip,
            "subnet_mask": subnet_mask,
            "gateway": gateway,
            "raw_response": data.hex(),
        }

        return DiscoveredDevice(
            mac_address=mac,
            ip_addresses=[ip],
            name=f"Lantronix Device ({ip})",
            manufacturer="Lantronix",
            device_type="Serial Device Server",
            description=f"Lantronix (configured: {config_ip})",
            discovered_by=["lantronix"],
            first_seen=datetime.now().isoformat(),
            last_seen=datetime.now().isoformat(),
            lantronix_data=lantronix_data,
        )
