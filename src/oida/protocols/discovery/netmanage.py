"""
Schneider Electric NetManage Discovery Protocol.

NetManage is a UDP-based discovery protocol used by Schneider Electric
EcoStruxure Machine Expert and related tools to discover CODESYS-based PLCs
(PacDrive, Modicon M580, LMC series, etc.).

Reverse Engineering Source:
    Elau.Netmanage.Core.dll (v23.0.22.0) from EcoStruxure Machine Expert
    Decompiled with ILSpy - key classes:
    - Elau.Netmanage.Core.Communication.Protocol.NetManageProtocol
    - Elau.Netmanage.Core.Communication.Protocol.NetManageProtocolHeader
    - Elau.Netmanage.Core.Communication.Checksum

Protocol Specification:
- Send Port: 27127 (UDP broadcast)
- Receive Port: 27126 (UDP)
- Encryption: XOR obfuscation with 59-byte static key
- Header: 30 bytes (MAC[18] + Command[4] + Version[2] + Checksum[2] + SizeOfAll[4])
- Checksum: RFC 1071 Internet Checksum (one's complement of 16-bit word sum)
- Data: Variable-length data blocks with size[4] + format[2] + content

Commands:
- ResponsePublish = 0 (device response with full info)
- RequestPublish = 1000 (discovery broadcast)
- RequestSignal = 1001 (blink/beep to identify device)
- RequestEditCommunication = 1002 (change IP/network config - requires auth)
- RequestInfoP600 = 1003 (extended info for P600 controllers)

Usage:
    # Active discovery
    scanner = NetManageScanner(interface="eth0", timeout=5, active=True)
    devices = scanner.scan()

    # Passive listening
    listener = NetManagePassiveListener(interface="eth0", timeout=30)
    devices = listener.scan()
    devices = listener.scan()
"""

import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from oida.protocols.discovery.base import PassiveListenerBase
from oida.protocols.discovery.core import DiscoveredDevice, validate_interface, validate_timeout
from oida.utils.rate_limiter import sendto
from oida.utils.ics_logger import get_module_logger

logger = get_module_logger(__name__)

# Protocol constants
NETMANAGE_SEND_PORT = 27127
NETMANAGE_RECV_PORT = 27126
NETMANAGE_BROADCAST = "255.255.255.255"

# Header sizes
HEADER_SIZE = 30

# Checksum offset in header
CHECKSUM_OFFSET = 24

# =============================================================================
# NetManage Protocol Commands
# =============================================================================
#
# ResponsePublish (0):
#   Device response to discovery. Contains all device information:
#   MAC, IP, subnet, gateway, controller type, firmware version,
#   project name/date/author, boot mode, DHCP state, NetBIOS name, etc.
#
# RequestPublish (1000):
#   Discovery broadcast request ("who's there?").
#   Sent to MAC FF:FF:FF:FF:FF:FF. All devices respond with ResponsePublish.
#   Implementation: RefreshCommunicationBuilder in C# source.
#
# RequestSignal (1001):
#   Physical device identification - makes device blink LEDs or beep.
#   Sent to specific device MAC address.
#   Data block contains:
#     - mode: 0=off, 1=optical (blink), 2=acoustic (beep), etc.
#     - signalTimeout: Duration in ms (default 120000 = 2 minutes)
#   Implementation: SignalBuilder in C# source.
#   Example packet structure:
#     Header (30 bytes) + DataBlock with mode + timeout as string elements
#
# RequestEditCommunication (1002):
#   Remote network configuration of device. REQUIRES AUTHENTICATION.
#   Sent to specific device MAC address.
#   Data block contains (all as string elements):
#     - user: Username for authentication
#     - password: Password for authentication
#     - ipAddress: New IP address
#     - ipAddressMode: 0=DoNothing, 1=SetParameter, 2=SetParameterAndStore
#     - subnetMask: New subnet mask
#     - subnetMaskMode: Same mode flags
#     - gateway: New gateway
#     - gatewayMode: Same mode flags
#     - netbios: NetBIOS name
#     - netbiosMode: Same mode flags
#     - bootMode: Boot configuration
#     - bootModeMode: Same mode flags
#     - bootInterfaceName: Network interface
#     - bootInterfaceNameMode: Same mode flags
#     - nodeName: Device name
#     - nodeNameMode: Same mode flags
#   Implementation: EditCommunicationBuilder in C# source.
#   WARNING: Can permanently change device network settings!
#
# RequestInfoP600 (1003):
#   Extended information request for PacDrive P600 controllers.
#   P600 devices have dual network interfaces with separate settings:
#     - P600_IP_Address, P600_SubNetMask, P600_Gateway
#     - P600_NetbiosName, P600_RoutingActivated, P600_GatewayStarted
#   Only relevant for legacy P600 hardware.
#
# =============================================================================

CMD_RESPONSE_PUBLISH = 0
CMD_REQUEST_PUBLISH = 1000
CMD_REQUEST_SIGNAL = 1001
CMD_REQUEST_EDIT_COMMUNICATION = 1002
CMD_REQUEST_INFO_P600 = 1003

COMMAND_NAMES = {
    CMD_RESPONSE_PUBLISH: "ResponsePublish",
    CMD_REQUEST_PUBLISH: "RequestPublish",
    CMD_REQUEST_SIGNAL: "RequestSignal",
    CMD_REQUEST_EDIT_COMMUNICATION: "RequestEditCommunication",
    CMD_REQUEST_INFO_P600: "RequestInfoP600",
}

# XOR obfuscation key (59 bytes)
# Original string: "üµai893;UIoiuaüq4mw0juwldiu@€rafös*ÜSMiejwif8epwnfSköos;µ,a"
NETMANAGE_KEY = bytes(
    [
        252,
        181,
        97,
        105,
        56,
        57,
        51,
        59,
        85,
        73,
        111,
        105,
        117,
        97,
        252,
        113,
        52,
        109,
        119,
        48,
        106,
        117,
        119,
        108,
        100,
        105,
        117,
        64,
        128,
        114,
        97,
        102,
        246,
        115,
        42,
        220,
        83,
        77,
        105,
        101,
        106,
        119,
        105,
        102,
        56,
        101,
        112,
        119,
        110,
        102,
        83,
        107,
        246,
        111,
        115,
        59,
        181,
        44,
        97,
    ]
)
NETMANAGE_KEY_LEN = len(NETMANAGE_KEY)


def xor_encode_decode(data: bytes) -> bytes:
    """XOR encode/decode data using NetManage key.

    The same function is used for both encoding and decoding
    since XOR is symmetric.

    Args:
        data: Data to encode/decode

    Returns:
        XOR'd data
    """
    result = bytearray(len(data))
    for i in range(len(data)):
        result[i] = data[i] ^ NETMANAGE_KEY[i % NETMANAGE_KEY_LEN]
    return bytes(result)


def calculate_checksum(data: bytes, checksum_offset: int = CHECKSUM_OFFSET) -> int:
    """Calculate NetManage checksum (RFC 1071 style Internet Checksum).

    This is a one's complement sum of 16-bit words with carry folding.
    The checksum field bytes are zeroed during calculation.

    Args:
        data: Full packet data
        checksum_offset: Offset of checksum field (2 bytes)

    Returns:
        Checksum value (uint16)
    """
    # Create a copy with checksum field zeroed
    buf = bytearray(data)
    buf[checksum_offset] = 0
    buf[checksum_offset + 1] = 0

    # Sum 16-bit words (little-endian)
    total = 0
    length = len(buf)
    i = 0
    while length > 1:
        total += (buf[i + 1] << 8) + buf[i]
        length -= 2
        i += 2

    # Handle odd byte
    if length > 0:
        total += buf[i]

    # Fold 32-bit sum to 16 bits
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16

    # One's complement
    return (~total) & 0xFFFF


def verify_checksum(data: bytes, checksum_offset: int = CHECKSUM_OFFSET) -> bool:
    """Verify NetManage packet checksum.

    Args:
        data: Full decoded packet data
        checksum_offset: Offset of checksum field

    Returns:
        True if checksum is valid
    """
    if len(data) < checksum_offset + 2:
        return False
    stored_checksum = struct.unpack_from("<H", data, checksum_offset)[0]
    calculated = calculate_checksum(data, checksum_offset)
    return stored_checksum == calculated


@dataclass
class NetManageHeader:
    """NetManage protocol header (30 bytes)."""

    mac_address: str  # 17 chars + null = 18 bytes
    command: int  # 4 bytes, int32 LE
    version: int  # 2 bytes, int16 LE
    checksum: int  # 2 bytes, uint16 LE
    size_of_all: int  # 4 bytes, int32 LE

    @classmethod
    def from_bytes(cls, data: bytes) -> Optional["NetManageHeader"]:
        """Parse header from decoded bytes.

        Args:
            data: Decoded packet data (at least 30 bytes)

        Returns:
            NetManageHeader or None if invalid
        """
        if len(data) < HEADER_SIZE:
            return None

        try:
            # MAC address is 17 chars + null terminator
            mac_raw = data[0:17]
            mac_address = mac_raw.decode("ascii", errors="replace").rstrip("\x00")

            # Parse remaining fields (little-endian)
            command = struct.unpack_from("<i", data, 18)[0]
            version = struct.unpack_from("<h", data, 22)[0]
            checksum = struct.unpack_from("<H", data, 24)[0]
            size_of_all = struct.unpack_from("<i", data, 26)[0]

            return cls(
                mac_address=mac_address,
                command=command,
                version=version,
                checksum=checksum,
                size_of_all=size_of_all,
            )
        except Exception as e:
            logger.debug(f"Failed to parse NetManage header: {e}")
            return None

    def to_bytes(self) -> bytes:
        """Serialize header to bytes.

        Returns:
            30-byte header
        """
        result = bytearray(HEADER_SIZE)

        # MAC address (17 chars + null)
        mac_bytes = self.mac_address.encode("ascii")[:17]
        result[0 : len(mac_bytes)] = mac_bytes
        result[17] = 0  # null terminator

        # Command, version, checksum, size_of_all (little-endian)
        struct.pack_into("<i", result, 18, self.command)
        struct.pack_into("<h", result, 22, self.version)
        struct.pack_into("<H", result, 24, self.checksum)
        struct.pack_into("<i", result, 26, self.size_of_all)

        return bytes(result)

    @property
    def command_name(self) -> str:
        """Get human-readable command name."""
        return COMMAND_NAMES.get(self.command, f"Unknown({self.command})")


@dataclass
class NetManageDataBlock:
    """NetManage data block (header 6 bytes + data)."""

    size: int  # 4 bytes, int32 LE
    format: int  # 2 bytes, int16 LE (0=String, 1=Structure)
    data: bytes  # Variable length

    @classmethod
    def from_bytes(cls, data: bytes, offset: int = 0) -> Optional["NetManageDataBlock"]:
        """Parse data block from bytes.

        Args:
            data: Packet data
            offset: Start offset

        Returns:
            NetManageDataBlock or None if invalid
        """
        if len(data) < offset + 6:
            return None

        try:
            size = struct.unpack_from("<i", data, offset)[0]
            format_val = struct.unpack_from("<h", data, offset + 4)[0]

            # Data follows the 6-byte header
            data_start = offset + 6
            data_len = size - 6  # size includes header

            if data_len < 0 or len(data) < data_start + data_len:
                # Header-declared size is bogus/truncated: clamp to remaining bytes
                data_len = max(0, len(data) - data_start)

            block_data = data[data_start : data_start + data_len]

            return cls(size=size, format=format_val, data=block_data)
        except Exception as e:
            logger.debug(f"Failed to parse NetManage data block: {e}")
            return None

    def get_string_values(self) -> List[str]:
        """Parse string format data block into values.

        Returns:
            List of string values (newline-separated in packet)
        """
        if self.format != 0:  # Not string format
            return []

        try:
            # Data is ISO-8859-1 encoded, newline-separated
            text = self.data.decode("iso-8859-1", errors="replace")
            # Remove trailing null
            text = text.rstrip("\x00")
            return text.split("\n")
        except Exception as e:
            logger.debug(f"Failed to parse string values: {e}")
            return []


@dataclass
class NetManageDevice:
    """Discovered NetManage device information."""

    ip_address: str
    mac_address: str
    device_name: str = ""
    device_type: str = ""
    firmware_version: str = ""
    serial_number: str = ""
    vendor: str = "Schneider Electric"
    protocol_version: int = 1
    boot_mode: str = ""
    ip_mode: str = ""  # DHCP/Static
    subnet_mask: str = ""
    gateway: str = ""
    netbios_name: str = ""
    raw_values: List[str] = field(default_factory=list)
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)

    def to_discovered_device(self) -> DiscoveredDevice:
        """Convert to standard DiscoveredDevice.

        Prior to the fix this passed kwargs (`ip`, `mac`, `hostname`,
        `vendor`, `protocol`, `metadata`, raw `datetime`) that don't
        exist on DiscoveredDevice - every Schneider PLC discovery
        raised TypeError; passive listener swallowed it silently;
        CHANGELOG advertised a non-functional feature. Real fields are
        `mac_address`, `ip_addresses: List[str]`, `name`, `manufacturer`,
        `discovered_by: List[str]`, ISO-string `first_seen` / `last_seen`,
        and `*_data: Optional[Dict]` per-protocol payload buckets.
        """
        return DiscoveredDevice(
            mac_address=self.mac_address.lower() if self.mac_address else "",
            ip_addresses=[self.ip_address] if self.ip_address else [],
            name=self.device_name or self.netbios_name,
            manufacturer=self.vendor or "",
            device_type=self.device_type or "PLC",
            discovered_by=["netmanage"],
            first_seen=(
                self.first_seen.isoformat()
                if isinstance(self.first_seen, datetime)
                else str(self.first_seen)
            ),
            last_seen=(
                self.last_seen.isoformat()
                if isinstance(self.last_seen, datetime)
                else str(self.last_seen)
            ),
            netmanage_data={
                "protocol_version": self.protocol_version,
                "firmware_version": self.firmware_version,
                "serial_number": self.serial_number,
                "boot_mode": self.boot_mode,
                "ip_mode": self.ip_mode,
                "subnet_mask": self.subnet_mask,
                "gateway": self.gateway,
                "netbios_name": self.netbios_name,
                "raw_values": self.raw_values,
            },
        )


def parse_response_values(values: List[str]) -> Dict[str, str]:
    """Parse ResponsePublish values into named fields.

    The response contains ~32 newline-separated values in a specific order.
    Based on reverse engineering of NetManage protocol.

    Args:
        values: List of string values from data block

    Returns:
        Dict with named fields
    """
    result = {}

    # Known field positions (0-indexed)
    field_map = {
        0: "mac_address",
        1: "device_name",
        2: "ip_mode",  # 0=static, 1=dhcp
        3: "ip_address",
        4: "subnet_mask",
        5: "gateway",
        6: "netbios_name",
        7: "boot_mode",
        8: "firmware_version",
        9: "device_type",
        10: "serial_number",
        # ... more fields exist
    }

    for idx, name in field_map.items():
        if idx < len(values):
            result[name] = values[idx]

    return result


class NetManageScanner:
    """Active NetManage device discovery scanner."""

    def __init__(
        self,
        interface: str,
        timeout: int = 5,
        active: bool = True,
        target: Optional[str] = None,
    ):
        """Initialize scanner.

        Args:
            interface: Network interface to use
            timeout: Discovery timeout in seconds
            active: If True, send discovery requests
            target: Optional target IP (default: broadcast)
        """
        self.interface = validate_interface(interface)
        self.timeout = validate_timeout(timeout)
        self.active = active
        self.target = target or NETMANAGE_BROADCAST
        self.discovered_devices: Dict[str, NetManageDevice] = {}
        self._lock = threading.Lock()

    def _create_discovery_request(self, mac_filter: str = "FF:FF:FF:FF:FF:FF") -> bytes:
        """Create a discovery request packet.

        Args:
            mac_filter: MAC address filter (FF:FF:FF:FF:FF:FF for all)

        Returns:
            Encoded packet ready to send
        """
        # Create header
        header = NetManageHeader(
            mac_address=mac_filter,
            command=CMD_REQUEST_PUBLISH,
            version=1,
            checksum=0,  # Will be calculated
            size_of_all=HEADER_SIZE,  # Just header, no data block
        )

        packet = bytearray(header.to_bytes())

        # Calculate and set checksum
        checksum = calculate_checksum(packet)
        struct.pack_into("<H", packet, CHECKSUM_OFFSET, checksum)

        # XOR encode
        return xor_encode_decode(bytes(packet))

    def _parse_response(self, data: bytes, addr: Tuple[str, int]) -> Optional[NetManageDevice]:
        """Parse a NetManage response packet.

        Args:
            data: Raw received data
            addr: Source address (ip, port)

        Returns:
            NetManageDevice or None if invalid
        """
        ip = addr[0]

        # Decode XOR
        decoded = xor_encode_decode(data)

        # Parse header
        header = NetManageHeader.from_bytes(decoded)
        if not header:
            logger.debug(f"Invalid header from {ip}")
            return None

        # Verify checksum
        if not verify_checksum(decoded):
            logger.debug(f"Checksum mismatch from {ip}")
            # Continue anyway - some implementations may have bugs

        # Check if it's a response
        if header.command != CMD_RESPONSE_PUBLISH:
            logger.debug(f"Not a response from {ip}: cmd={header.command_name}")
            return None

        # Parse data block if present
        values = []
        if len(decoded) > HEADER_SIZE:
            data_block = NetManageDataBlock.from_bytes(decoded, HEADER_SIZE)
            if data_block:
                values = data_block.get_string_values()

        # Parse values into fields
        fields = parse_response_values(values)

        # Create device
        device = NetManageDevice(
            ip_address=ip,
            mac_address=header.mac_address,
            device_name=fields.get("device_name", ""),
            device_type=fields.get("device_type", ""),
            firmware_version=fields.get("firmware_version", ""),
            serial_number=fields.get("serial_number", ""),
            boot_mode=fields.get("boot_mode", ""),
            ip_mode="DHCP" if fields.get("ip_mode") == "1" else "Static",
            subnet_mask=fields.get("subnet_mask", ""),
            gateway=fields.get("gateway", ""),
            netbios_name=fields.get("netbios_name", ""),
            protocol_version=header.version,
            raw_values=values,
        )

        return device

    def scan(self) -> Dict[str, DiscoveredDevice]:
        """Perform NetManage discovery scan.

        Returns:
            Dict mapping IP addresses to DiscoveredDevice
        """
        sock = None
        try:
            # Create UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.settimeout(1.0)

            # Bind to receive port
            sock.bind(("", NETMANAGE_RECV_PORT))

            # Try to bind to interface
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, self.interface.encode())
            except (OSError, AttributeError) as e:
                logger.debug(f"SO_BINDTODEVICE failed for {self.interface}: {e}")

            # Send discovery request (if active mode)
            if self.active:
                request = self._create_discovery_request()
                sendto(sock, request, (self.target, NETMANAGE_SEND_PORT))
                logger.debug(f"Sent NetManage discovery to {self.target}:{NETMANAGE_SEND_PORT}")

            # Collect responses
            start_time = time.time()
            while time.time() - start_time < self.timeout:
                try:
                    data, addr = sock.recvfrom(4096)
                    device = self._parse_response(data, addr)
                    if device:
                        with self._lock:
                            key = device.ip_address
                            if key in self.discovered_devices:
                                self.discovered_devices[key].last_seen = datetime.now()
                            else:
                                self.discovered_devices[key] = device
                                logger.info(
                                    f"Discovered: {device.ip_address} - "
                                    f"{device.device_name or device.mac_address}"
                                )
                except TimeoutError:
                    continue
                except OSError as e:
                    logger.debug(f"Receive error: {e}")

        except OSError as e:
            logger.error(f"Socket error: {e}")
        finally:
            if sock:
                try:
                    sock.close()
                except OSError as e:
                    logger.debug(f"sock.close(): {e}")

        # Convert to DiscoveredDevice
        return {ip: dev.to_discovered_device() for ip, dev in self.discovered_devices.items()}

    def get_raw_devices(self) -> Dict[str, NetManageDevice]:
        """Get raw NetManageDevice objects with full details."""
        return self.discovered_devices.copy()


class NetManagePassiveListener(PassiveListenerBase):
    """Passive NetManage traffic listener using scapy."""

    PROTOCOL_NAME = "netmanage-passive"
    BPF_FILTER = f"udp port {NETMANAGE_SEND_PORT} or udp port {NETMANAGE_RECV_PORT}"

    def __init__(
        self,
        interface: str,
        timeout: int = 30,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        self.netmanage_devices: Dict[str, NetManageDevice] = {}

    def process_packet(self, packet: Any) -> None:
        """Process a captured packet.

        Args:
            packet: Scapy packet
        """
        try:
            # Check for UDP
            if not packet.haslayer("UDP"):
                return

            udp = packet["UDP"]

            # Check ports
            if udp.sport not in (NETMANAGE_SEND_PORT, NETMANAGE_RECV_PORT) and udp.dport not in (
                NETMANAGE_SEND_PORT,
                NETMANAGE_RECV_PORT,
            ):
                return

            # Get IP layer
            if not packet.haslayer("IP"):
                return

            ip = packet["IP"]
            src_ip = ip.src

            # Get payload
            if not packet.haslayer("Raw"):
                return

            raw_data = bytes(packet["Raw"].load)
            if len(raw_data) < HEADER_SIZE:
                return

            # Decode and parse
            decoded = xor_encode_decode(raw_data)
            header = NetManageHeader.from_bytes(decoded)

            if not header:
                return

            # Log the packet type
            logger.debug(f"NetManage {header.command_name} from {src_ip} MAC={header.mac_address}")

            # For responses, extract device info
            if header.command == CMD_RESPONSE_PUBLISH:
                values = []
                if len(decoded) > HEADER_SIZE:
                    data_block = NetManageDataBlock.from_bytes(decoded, HEADER_SIZE)
                    if data_block:
                        values = data_block.get_string_values()

                fields = parse_response_values(values)

                device = NetManageDevice(
                    ip_address=src_ip,
                    mac_address=header.mac_address,
                    device_name=fields.get("device_name", ""),
                    device_type=fields.get("device_type", ""),
                    firmware_version=fields.get("firmware_version", ""),
                    serial_number=fields.get("serial_number", ""),
                    boot_mode=fields.get("boot_mode", ""),
                    ip_mode="DHCP" if fields.get("ip_mode") == "1" else "Static",
                    subnet_mask=fields.get("subnet_mask", ""),
                    gateway=fields.get("gateway", ""),
                    netbios_name=fields.get("netbios_name", ""),
                    protocol_version=header.version,
                    raw_values=values,
                )

                with self._lock:
                    key = src_ip
                    if key in self.netmanage_devices:
                        self.netmanage_devices[key].last_seen = datetime.now()
                    else:
                        self.netmanage_devices[key] = device
                        self.discovered_devices[key] = device.to_discovered_device()

                        if self.nxc_logger:
                            self.nxc_logger.success(
                                f"NetManage: {src_ip} - {device.device_name or device.mac_address}"
                            )

        except Exception as e:
            logger.debug(f"Error processing NetManage packet: {e}")

    def get_raw_devices(self) -> Dict[str, NetManageDevice]:
        """Get raw NetManageDevice objects with full details."""
        return self.netmanage_devices.copy()


# Convenience functions for quick discovery
def discover_netmanage(
    interface: str = "eth0",
    timeout: int = 5,
    active: bool = True,
) -> Dict[str, DiscoveredDevice]:
    """Quick NetManage discovery.

    Args:
        interface: Network interface
        timeout: Discovery timeout
        active: Send discovery requests (True) or passive listen (False)

    Returns:
        Dict of discovered devices
    """
    if active:
        scanner = NetManageScanner(interface=interface, timeout=timeout, active=True)
    else:
        scanner = NetManagePassiveListener(interface=interface, timeout=timeout)

    return scanner.scan()


def decode_netmanage_packet(
    data: bytes,
) -> Optional[Tuple[NetManageHeader, Optional[NetManageDataBlock]]]:
    """Decode a raw NetManage packet.

    Args:
        data: Raw packet bytes

    Returns:
        Tuple of (header, data_block) or None if invalid
    """
    decoded = xor_encode_decode(data)
    header = NetManageHeader.from_bytes(decoded)

    if not header:
        return None

    data_block = None
    if len(decoded) > HEADER_SIZE:
        data_block = NetManageDataBlock.from_bytes(decoded, HEADER_SIZE)

    return header, data_block
