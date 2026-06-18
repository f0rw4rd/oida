"""
FINS/Omron UDP broadcast discovery.

FINS (Factory Interface Network Service) is Omron's protocol for PLC communication.
Omron devices respond to UDP broadcasts on port 9600.
"""

import struct
import threading
import time
from datetime import datetime
from typing import Dict, Optional

from .base import PassiveListenerBase
from .core import (
    DiscoveredDevice,
    create_udp_socket,
    get_all_broadcast_addresses,
    get_interface_network,
    is_valid_discovered_ip,
    is_valid_mac,
    validate_interface,
    validate_subnet,
    validate_timeout,
)
from ...utils.rate_limiter import sendto
from ...utils.ics_logger import get_module_logger

logger = get_module_logger(__name__)

# FINS UDP port
FINS_UDP_PORT = 9600

# FINS command codes
FINS_CMD_CONTROLLER_DATA_READ = 0x0501  # Read controller data
FINS_CMD_CONTROLLER_STATUS_READ = 0x0601  # Read controller status

# FINS header structure (for UDP)
# ICF: Information Control Field
# RSV: Reserved
# GCT: Gateway Count
# DNA: Destination Network Address
# DA1: Destination Node Address
# DA2: Destination Unit Address
# SNA: Source Network Address
# SA1: Source Node Address
# SA2: Source Unit Address
# SID: Service ID


class FINSScanner:
    """FINS/Omron UDP broadcast discovery scanner.

    Sends FINS UDP broadcast to discover Omron PLCs on the network.
    """

    def __init__(self, interface: str, subnet: Optional[str] = None, timeout: float = 3.0):
        self.interface = validate_interface(interface)
        self.subnet = validate_subnet(subnet)
        self.timeout = validate_timeout(timeout)
        self.discovered_devices: Dict[str, DiscoveredDevice] = {}
        self._lock = threading.Lock()

    def scan(self) -> Dict[str, DiscoveredDevice]:
        """Send FINS broadcast and collect responses."""
        logger.debug(f"FINS: Scanning on {self.interface} (timeout: {self.timeout}s)")

        # Auto-detect subnet if not specified
        if not self.subnet:
            self.subnet = get_interface_network(self.interface)

        sock = None
        try:
            sock = create_udp_socket(
                self.interface, timeout=self.timeout, broadcast=True, bind_port=FINS_UDP_PORT
            )

            # Build FINS UDP header + Controller Data Read command
            fins_packet = self._build_fins_request()

            # Send to all broadcast addresses to reach devices on different subnets
            broadcast_addrs = get_all_broadcast_addresses(self.interface, self.subnet)
            for i, broadcast_addr in enumerate(broadcast_addrs):
                sendto(sock, fins_packet, (broadcast_addr, FINS_UDP_PORT))
                logger.debug(f"FINS: Sent broadcast to {broadcast_addr}:{FINS_UDP_PORT}")
                # Small delay between broadcasts
                if i < len(broadcast_addrs) - 1:
                    time.sleep(0.1)

            # Collect responses
            start_time = time.time()
            while time.time() - start_time < self.timeout:
                try:
                    sock.settimeout(max(0.1, self.timeout - (time.time() - start_time)))
                    data, addr = sock.recvfrom(1024)
                    self._process_response(data, addr)
                except TimeoutError:
                    break
                except OSError as e:
                    logger.debug(f"FINS: Receive error: {e}")

        except OSError as e:
            logger.debug(f"FINS: Socket error: {e}")
        except Exception as e:
            logger.debug(f"FINS: Scan error: {e}")
        finally:
            if sock:
                try:
                    sock.close()
                except OSError as e:
                    logger.debug(f"sock.close(): {e}")

        logger.debug(f"FINS: Found {len(self.discovered_devices)} devices")
        return self.discovered_devices

    def _build_fins_request(self) -> bytes:
        """Build FINS UDP request packet for controller data read."""
        # FINS UDP header (10 bytes)
        icf = 0x80  # Command, need response
        rsv = 0x00  # Reserved
        gct = 0x02  # Gateway count
        dna = 0x00  # Destination network (local)
        da1 = 0xFF  # Destination node (broadcast)
        da2 = 0x00  # Destination unit (CPU)
        sna = 0x00  # Source network (local)
        sa1 = 0x00  # Source node (auto)
        sa2 = 0x00  # Source unit
        sid = 0x00  # Service ID

        header = struct.pack("BBBBBBBBBB", icf, rsv, gct, dna, da1, da2, sna, sa1, sa2, sid)

        # FINS command: Controller Data Read (MRC=0x05, SRC=0x01 → 0x0501)
        command = struct.pack(">H", 0x0501)

        return header + command

    def _process_response(self, data: bytes, addr: tuple) -> None:
        """Process FINS response packet."""
        if len(data) < 14:  # Minimum: 10 byte header + 4 byte response
            return

        ip_addr = addr[0]

        # Filter by subnet if specified
        if self.subnet:
            import ipaddress

            try:
                network = ipaddress.IPv4Network(self.subnet, strict=False)
                if ipaddress.IPv4Address(ip_addr) not in network:
                    logger.debug(f"FINS: Ignoring response from {ip_addr} (not in {self.subnet})")
                    return
            except ValueError as e:
                logger.debug(f"Failed to get network: {e}")

        try:
            # Parse FINS header (minimum 10 bytes)
            if len(data) < 10:
                return

            icf = data[0]
            sna = data[6]
            sa1 = data[7]  # Source node = responder's node number
            sa2 = data[8]

            # Validate FINS response:
            # - ICF bit 6 (0x40) should be set for response
            # - ICF bit 7 (0x80) indicates command/response type
            # Valid response ICF: 0xC0, 0xC1, 0xD0, 0xD1
            if not (icf & 0x40):
                logger.debug(f"FINS: Invalid ICF from {ip_addr}: 0x{icf:02x} (not a response)")
                return

            # Response code (2 bytes after header)
            if len(data) >= 14:
                main_code = data[12]
                sub_code = data[13]

                if main_code != 0 or sub_code != 0:
                    logger.debug(
                        f"FINS: Error response from {ip_addr}: {main_code:02x}{sub_code:02x}"
                    )
                    # Still record the device even with error

            # Extract controller data if present
            controller_model = ""
            controller_version = ""

            if len(data) > 14:
                # Controller data starts after response code
                ctrl_data = data[14:]

                # Try to extract model info (varies by device)
                # Format depends on specific Omron model
                if len(ctrl_data) >= 20:
                    # Model string is often in first 20 bytes
                    try:
                        model_bytes = ctrl_data[:20]
                        controller_model = (
                            model_bytes.decode("ascii", errors="ignore").strip("\x00").strip()
                        )
                    except UnicodeDecodeError as e:
                        logger.debug(f"FINS: model decode error: {e}")

                if len(ctrl_data) >= 40:
                    # Version info often follows
                    try:
                        version_bytes = ctrl_data[20:40]
                        controller_version = (
                            version_bytes.decode("ascii", errors="ignore").strip("\x00").strip()
                        )
                    except UnicodeDecodeError as e:
                        logger.debug(f"FINS: version decode error: {e}")

            with self._lock:
                device_key = f"ip:{ip_addr}"

                if device_key not in self.discovered_devices:
                    device = DiscoveredDevice(
                        mac_address="",  # FINS doesn't provide MAC
                        ip_addresses=[ip_addr],
                        name="",
                        manufacturer="Omron",
                        model=controller_model,
                        device_type="PLC",
                        discovered_by=["fins"],
                        first_seen=datetime.now().isoformat(),
                        last_seen=datetime.now().isoformat(),
                    )

                    # Store FINS-specific data
                    device.fins_data = {
                        "node_address": sa1,
                        "unit_address": sa2,
                        "network_address": sna,
                        "controller_model": controller_model,
                        "controller_version": controller_version,
                        "protocol": "FINS/UDP",
                        "port": FINS_UDP_PORT,
                    }

                    self.discovered_devices[device_key] = device
                    logger.debug(
                        f"FINS: {ip_addr} node={sa1} model={controller_model or 'unknown'}"
                    )

        except Exception as e:
            logger.debug(f"FINS: Parse error for {ip_addr}: {e}")


class FINSPassiveListener(PassiveListenerBase):
    """Passive FINS traffic listener.

    Listens for FINS UDP traffic to discover Omron devices without sending probes.

    Usage:
        # Live capture
        listener = FINSPassiveListener(interface="eth0", timeout=30)
        devices = listener.scan()

        # Testing - feed packets directly
        listener = FINSPassiveListener(interface="eth0")
        listener.feed_packet(mock_fins_packet)
    """

    PROTOCOL_NAME = "fins-passive"
    BPF_FILTER = f"udp port {FINS_UDP_PORT}"

    def should_process_packet(self, packet) -> bool:
        """Check if packet is a FINS packet."""
        from scapy.all import UDP, IP

        if UDP not in packet or IP not in packet:
            return False
        return packet[UDP].dport == FINS_UDP_PORT or packet[UDP].sport == FINS_UDP_PORT

    def process_packet(self, packet) -> None:
        """Process captured FINS packet."""
        from scapy.all import IP, Ether

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Extract MAC from Ethernet layer if available
        src_mac = ""
        dst_mac = ""
        if Ether in packet:
            src_mac = packet[Ether].src
            dst_mac = packet[Ether].dst

        # Record both source and destination if they're using FINS
        for ip_addr, mac_addr in [(src_ip, src_mac), (dst_ip, dst_mac)]:
            # Use central validation (excludes local IPs, broadcast, etc.)
            if not is_valid_discovered_ip(ip_addr, self.interface):
                continue

            # Filter out broadcast/multicast MACs
            if not is_valid_mac(mac_addr):
                continue

            with self._lock:
                # Use MAC as key if available, otherwise fall back to IP
                device_key = mac_addr if mac_addr else f"ip:{ip_addr}"
                if device_key not in self.discovered_devices:
                    device = DiscoveredDevice(
                        mac_address=mac_addr,
                        ip_addresses=[ip_addr],
                        manufacturer="Omron",
                        device_type="PLC",
                        discovered_by=["fins-passive"],
                        first_seen=datetime.now().isoformat(),
                        last_seen=datetime.now().isoformat(),
                    )
                    device.fins_data = {
                        "protocol": "FINS/UDP",
                        "port": FINS_UDP_PORT,
                        "passive": True,
                    }
                    self.discovered_devices[device_key] = device
                    logger.debug(f"FINS passive: {ip_addr}")
                else:
                    self.discovered_devices[device_key].last_seen = datetime.now().isoformat()
