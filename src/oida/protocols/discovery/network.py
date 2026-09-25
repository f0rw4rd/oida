"""
Network infrastructure protocol scanners.

Contains:
- LLMNRScanner: LLMNR (Windows local name resolution)
- CDPPassiveListener: Cisco Discovery Protocol
- NetBIOSScanner: NetBIOS name service discovery
- STPPassiveListener: Spanning Tree Protocol BPDU listener
"""

import socket
import struct
import threading
import time
from datetime import datetime
from typing import Dict, List, Optional, Set

from oida.protocols.discovery.core import (
    DiscoveredDevice,
    bind_socket_to_interface,
    create_udp_socket,
    get_all_broadcast_addresses,
    get_interface_ip,
    get_interface_network,
    validate_interface,
    validate_subnet,
    validate_timeout,
)
from oida.utils.rate_limiter import sendto
from oida.utils.ics_logger import get_module_logger
from oida.utils.lazy_import import lazy_import

_scapy_all = lazy_import("scapy.all", "discovery")
_scapy_netbios = lazy_import("scapy.layers.netbios", "discovery")

logger = get_module_logger(__name__)


class LLMNRScanner:
    """LLMNR (Link-Local Multicast Name Resolution) scanner

    Microsoft's alternative to mDNS for local name resolution.
    Multicast address: 224.0.0.252:5355 (IPv4)
    """

    LLMNR_MULTICAST_ADDR = "224.0.0.252"
    LLMNR_PORT = 5355

    def __init__(self, interface: str, subnet: Optional[str] = None, timeout: int = 10):
        self.interface = validate_interface(interface)
        self.subnet = validate_subnet(subnet)
        self.timeout = validate_timeout(timeout)
        self.discovered_devices: Dict[str, DiscoveredDevice] = {}
        self._lock = threading.Lock()

    def scan(self) -> Dict[str, DiscoveredDevice]:
        """Send LLMNR queries to discover Windows hosts"""
        try:
            # Get hosts to query from subnet
            target_subnet = self.subnet
            if not target_subnet:
                target_subnet = get_interface_network(self.interface)

            if target_subnet:
                # Active: Query each host individually
                self._active_scan(target_subnet)

            # Also do passive listening for LLMNR traffic
            self._passive_listen()

            logger.info(f"LLMNR found {len(self.discovered_devices)} devices")

        except Exception as e:
            logger.error(f"LLMNR error: {e}")

        return self.discovered_devices

    def _passive_listen(self) -> None:
        """Listen for LLMNR queries/responses on multicast"""
        # Get interface IP for multicast membership
        iface_ip = get_interface_ip(self.interface)
        if not iface_ip:
            logger.debug(f"LLMNR: Could not get IP for {self.interface}, skipping passive")
            return

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.settimeout(2.0)

                # Bind to interface - prefer SO_BINDTODEVICE, fall back to IP
                if bind_socket_to_interface(sock, self.interface):
                    try:
                        sock.bind(("", self.LLMNR_PORT))
                    except OSError:
                        sock.bind(("", 0))
                else:
                    try:
                        sock.bind((iface_ip, self.LLMNR_PORT))
                    except OSError:
                        sock.bind((iface_ip, 0))

                # Join multicast group on specific interface
                try:
                    mreq = socket.inet_aton(self.LLMNR_MULTICAST_ADDR) + socket.inet_aton(iface_ip)
                    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
                except OSError as e:
                    # Multicast join may fail on some interfaces
                    logger.debug(f"LLMNR: IP_ADD_MEMBERSHIP join failed: {e}")

                start_time = time.time()
                while time.time() - start_time < min(self.timeout, 5):
                    try:
                        data, addr = sock.recvfrom(1024)
                        self._parse_llmnr_response(data, addr[0])
                    except TimeoutError:
                        continue
                    except OSError:
                        pass  # Network error during receive
            finally:
                sock.close()

        except Exception as e:
            logger.debug(f"LLMNR passive listen error: {e}")

    def _active_scan(self, subnet: str) -> None:
        """Send LLMNR queries to hosts in subnet"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.settimeout(0.5)

                # Try to bind to interface
                try:
                    sock.setsockopt(
                        socket.SOL_SOCKET, socket.SO_BINDTODEVICE, self.interface.encode()
                    )
                except (OSError, AttributeError) as e:
                    logger.debug(
                        f"sock.setsockopt(: {e}"
                    )  # SO_BINDTODEVICE may not be available or permitted

                # Build LLMNR queries using Scapy's DNS layer
                from scapy.layers.dns import DNS, DNSQR

                transaction_id = 0x1234

                # Query for "WPAD" (common Windows name)
                query = DNS(
                    id=transaction_id,
                    qr=0,
                    rd=0,
                    qd=DNSQR(qname="WPAD", qtype="A", qclass="IN"),
                )
                sendto(sock, bytes(query), (self.LLMNR_MULTICAST_ADDR, self.LLMNR_PORT))

                # Also query for common hostnames with delays for OT safety
                common_names = ["WORKSTATION", "DESKTOP", "SERVER", "PC"]
                for name in common_names:
                    # 200ms delay between queries to avoid packet bursts
                    time.sleep(0.2)
                    query = DNS(
                        id=transaction_id,
                        qr=0,
                        rd=0,
                        qd=DNSQR(qname=name, qtype="A", qclass="IN"),
                    )
                    sendto(sock, bytes(query), (self.LLMNR_MULTICAST_ADDR, self.LLMNR_PORT))

                # Collect responses
                start_time = time.time()
                while time.time() - start_time < min(self.timeout, 5):
                    try:
                        data, addr = sock.recvfrom(1024)
                        self._parse_llmnr_response(data, addr[0])
                    except TimeoutError:
                        continue
                    except OSError:
                        pass  # Network error during receive
            finally:
                sock.close()

        except Exception as e:
            logger.debug(f"LLMNR active scan error: {e}")

    def _parse_llmnr_response(self, data: bytes, ip: str) -> None:
        """Parse LLMNR response packet using Scapy's DNS layer"""
        try:
            from scapy.layers.dns import DNS

            if len(data) < 12:
                return

            dns_resp = DNS(data)

            transaction_id = dns_resp.id
            is_response = bool(dns_resp.qr)

            # Extract name from query section or answer section
            name = ""
            if dns_resp.qd:
                qname = dns_resp.qd.qname
                if isinstance(qname, bytes):
                    name = qname.decode("ascii", errors="ignore").rstrip(".")
                else:
                    name = str(qname).rstrip(".")

            if name and ip:
                llmnr_data = {
                    "name": name,
                    "is_response": is_response,
                    "transaction_id": transaction_id,
                }

                with self._lock:
                    if ip not in self.discovered_devices:
                        device = DiscoveredDevice(
                            ip_addresses=[ip],
                            name=name,
                            discovered_by=["llmnr"],
                            first_seen=datetime.now().isoformat(),
                            last_seen=datetime.now().isoformat(),
                            llmnr_data=llmnr_data,
                        )
                        self.discovered_devices[ip] = device
                    else:
                        device = self.discovered_devices[ip]
                        device.llmnr_data = llmnr_data
                        if not device.name:
                            device.name = name
                        device.last_seen = datetime.now().isoformat()
                        if "llmnr" not in device.discovered_by:
                            device.discovered_by.append("llmnr")

        except Exception as e:
            logger.debug(f"Error parsing LLMNR response: {e}")


class CDPPassiveListener:
    """CDP (Cisco Discovery Protocol) passive listener.

    Captures CDP frames sent by Cisco network devices.
    CDP uses multicast MAC 01:00:0c:cc:cc:cc on Ethernet.

    Usage:
        # Live capture
        listener = CDPPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()

        # Testing - feed packets directly
        listener = CDPPassiveListener(interface="eth0")
        listener.feed_packet(mock_cdp_packet)
    """

    PROTOCOL_NAME = "cdp"
    BPF_FILTER = "ether dst 01:00:0c:cc:cc:cc"

    CDP_MULTICAST_MAC = "01:00:0c:cc:cc:cc"
    CDP_ETHERTYPE = 0x2000

    def __init__(self, interface: str, timeout: int = 60):
        _scapy_all()  # Ensure scapy is available
        self.interface = validate_interface(interface)

        self.timeout = validate_timeout(timeout)
        self.discovered_devices: Dict[str, DiscoveredDevice] = {}
        self._lock = threading.Lock()

    def scan(self) -> Dict[str, DiscoveredDevice]:
        """Run discovery via live capture."""
        return self._live_capture()

    def _live_capture(self) -> Dict[str, DiscoveredDevice]:
        """Listen for CDP frames."""
        if not _scapy_all.is_available:
            logger.warning("scapy not available, CDP discovery disabled")
            return self.discovered_devices
        scapy = _scapy_all()
        AsyncSniffer, conf = scapy.AsyncSniffer, scapy.conf

        conf.verb = 0
        logger.debug(f"CDP: Listening for frames on {self.interface} for {self.timeout}s")

        sniffer = None
        try:
            sniffer = AsyncSniffer(
                iface=self.interface,
                filter=self.BPF_FILTER,
                prn=self._safe_process_packet,
                store=False,
            )

            sniffer.start()
            time.sleep(self.timeout)
        except OSError as e:
            logger.debug(f"CDP: Interface error: {e}")
        except Exception as e:
            logger.debug(f"CDP: Sniffer error: {e}")
        finally:
            if sniffer and sniffer.running:
                try:
                    sniffer.stop()
                except OSError as e:
                    logger.debug(f"CDP: sniffer stop error: {e}")

        logger.debug(f"CDP: Found {len(self.discovered_devices)} devices")
        return self.discovered_devices

    def _safe_process_packet(self, packet) -> None:
        """Wrapper with error handling for packet processing."""
        try:
            if self.should_process_packet(packet):
                self.process_packet(packet)
        except Exception as e:
            logger.debug(f"CDP packet error: {e}")

    def should_process_packet(self, packet) -> bool:
        """Check if packet is a CDP frame."""
        from scapy.all import Ether

        if Ether not in packet:
            return False
        return packet[Ether].dst.lower() == self.CDP_MULTICAST_MAC.lower()

    def process_packet(self, packet) -> None:
        """Process CDP frame."""
        self._parse_cdp_frame(packet)

    # Testing API
    def feed_packet(self, packet) -> None:
        """Feed single packet for testing."""
        self._safe_process_packet(packet)

    def feed_packets(self, packets) -> Dict[str, DiscoveredDevice]:
        """Feed multiple packets, return results."""
        for pkt in packets:
            self._safe_process_packet(pkt)
        return self.discovered_devices

    def _parse_cdp_frame(self, packet) -> None:
        """Parse CDP frame using scapy's native CDP layer."""
        try:
            from scapy.all import Ether
            from scapy.contrib.cdp import (
                CDPv2_HDR,
                CDPMsgDeviceID,
                CDPMsgAddr,
                CDPMsgPortID,
                CDPMsgCapabilities,
                CDPMsgSoftwareVersion,
                CDPMsgPlatform,
                CDPMsgNativeVLAN,
                CDPMsgDuplex,
                CDPMsgMgmtAddr,
            )

            src_mac = packet[Ether].src

            # Check for CDPv2 header
            if CDPv2_HDR not in packet:
                return

            cdp_hdr = packet[CDPv2_HDR]
            version = cdp_hdr.vers
            ttl = cdp_hdr.ttl

            cdp_data = {
                "version": version,
                "ttl": ttl,
                "device_id": "",
                "addresses": [],
                "port_id": "",
                "capabilities": "",
                "software_version": "",
                "platform": "",
                "native_vlan": 0,
                "duplex": "",
                "management_addresses": [],
            }

            # Parse CDP TLVs using scapy's layers
            if CDPMsgDeviceID in packet:
                cdp_data["device_id"] = (
                    packet[CDPMsgDeviceID].val.decode("ascii", errors="ignore").rstrip("\x00")
                )

            if CDPMsgAddr in packet:
                cdp_data["addresses"] = self._extract_cdp_addresses(packet[CDPMsgAddr])

            if CDPMsgPortID in packet:
                cdp_data["port_id"] = (
                    packet[CDPMsgPortID].iface.decode("ascii", errors="ignore").rstrip("\x00")
                )

            if CDPMsgCapabilities in packet:
                caps = packet[CDPMsgCapabilities].cap
                cdp_data["capabilities"] = self._parse_cdp_capabilities(caps)

            if CDPMsgSoftwareVersion in packet:
                cdp_data["software_version"] = (
                    packet[CDPMsgSoftwareVersion]
                    .val.decode("ascii", errors="ignore")
                    .rstrip("\x00")
                )

            if CDPMsgPlatform in packet:
                cdp_data["platform"] = (
                    packet[CDPMsgPlatform].val.decode("ascii", errors="ignore").rstrip("\x00")
                )

            if CDPMsgNativeVLAN in packet:
                cdp_data["native_vlan"] = packet[CDPMsgNativeVLAN].vlan

            if CDPMsgDuplex in packet:
                cdp_data["duplex"] = "full" if packet[CDPMsgDuplex].duplex else "half"

            if CDPMsgMgmtAddr in packet:
                cdp_data["management_addresses"] = self._extract_cdp_addresses(
                    packet[CDPMsgMgmtAddr]
                )

            # Create device entry
            ip_addresses = cdp_data["addresses"] + cdp_data["management_addresses"]
            ip_addresses = list(set(ip_addresses))  # Deduplicate

            with self._lock:
                if src_mac not in self.discovered_devices:
                    device = DiscoveredDevice(
                        mac_address=src_mac,
                        ip_addresses=ip_addresses,
                        name=cdp_data["device_id"],
                        manufacturer="Cisco",
                        model=cdp_data["platform"],
                        description=cdp_data["software_version"],
                        device_type=cdp_data["capabilities"],
                        discovered_by=["cdp"],
                        first_seen=datetime.now().isoformat(),
                        last_seen=datetime.now().isoformat(),
                        cdp_data=cdp_data,
                    )
                    self.discovered_devices[src_mac] = device
                else:
                    device = self.discovered_devices[src_mac]
                    device.cdp_data = cdp_data
                    device.last_seen = datetime.now().isoformat()
                    # Update fields
                    if cdp_data["device_id"] and not device.name:
                        device.name = cdp_data["device_id"]
                    if cdp_data["platform"] and not device.model:
                        device.model = cdp_data["platform"]
                    for ip in ip_addresses:
                        if ip not in device.ip_addresses:
                            device.ip_addresses.append(ip)

        except Exception as e:
            logger.debug(f"Error parsing CDP frame: {e}")

    def _extract_cdp_addresses(self, addr_msg) -> List[str]:
        """Extract IP addresses from CDP address message using scapy."""
        addresses = []
        try:
            # CDPMsgAddr has naddr (count) and addr (list of CDPAddrRecord)
            if hasattr(addr_msg, "addr") and addr_msg.addr:
                for addr_record in addr_msg.addr:
                    if hasattr(addr_record, "addr"):
                        # Addr is bytes for IPv4
                        addr_bytes = addr_record.addr
                        if len(addr_bytes) == 4:  # IPv4
                            ip = socket.inet_ntoa(addr_bytes)
                            addresses.append(ip)
        except Exception as e:
            logger.debug(f"CDP: address extraction error: {e}")

        return addresses

    def _parse_cdp_capabilities(self, caps: int) -> str:
        """Parse CDP capabilities bitmask"""
        capabilities = []
        if caps & 0x01:
            capabilities.append("Router")
        if caps & 0x02:
            capabilities.append("Trans-Bridge")
        if caps & 0x04:
            capabilities.append("Source-Route-Bridge")
        if caps & 0x08:
            capabilities.append("Switch")
        if caps & 0x10:
            capabilities.append("Host")
        if caps & 0x20:
            capabilities.append("IGMP")
        if caps & 0x40:
            capabilities.append("Repeater")
        return ", ".join(capabilities) if capabilities else "Unknown"


class NetBIOSScanner:
    """NetBIOS Name Service discovery via broadcast queries"""

    NETBIOS_PORT = 137

    # NetBIOS suffix types
    SUFFIX_TYPES = {
        0x00: "Workstation",
        0x03: "Messenger Service",
        0x06: "RAS Server",
        0x1B: "Domain Master Browser",
        0x1C: "Domain Controllers",
        0x1D: "Master Browser",
        0x1E: "Browser Service Elections",
        0x1F: "NetDDE Service",
        0x20: "File Server",
        0x21: "RAS Client",
        0x22: "Exchange Interchange",
        0x23: "Exchange Store",
        0x24: "Exchange Directory",
        0x30: "Modem Sharing Server",
        0x31: "Modem Sharing Client",
        0x43: "SMS Clients Remote Control",
        0x44: "SMS Admin Remote Control Tool",
        0x45: "SMS Clients Remote Chat",
        0x46: "SMS Clients Remote Transfer",
        0x87: "Exchange MTA",
        0xBE: "Network Monitor Agent",
        0xBF: "Network Monitor Application",
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
        """Send NetBIOS name query broadcast and collect responses"""
        try:
            # Build NBT Node Status query for wildcard name (*)
            query = self._build_nbstat_query()

            sock = create_udp_socket(self.interface, timeout=0.5, broadcast=True)
            try:
                # Send broadcast to all broadcast addresses to reach devices on different subnets
                broadcast_addrs = get_all_broadcast_addresses(self.interface, self.subnet)
                for i, broadcast_addr in enumerate(broadcast_addrs):
                    logger.debug(
                        f"NetBIOS: Broadcasting NBSTAT query to {broadcast_addr}:{self.NETBIOS_PORT}"
                    )
                    sendto(sock, query, (broadcast_addr, self.NETBIOS_PORT))
                    # Small delay between broadcasts
                    if i < len(broadcast_addrs) - 1:
                        time.sleep(0.1)

                # Collect responses
                start_time = time.time()
                seen_ips: Set[str] = set()

                while time.time() - start_time < self.timeout:
                    try:
                        data, addr = sock.recvfrom(4096)
                        ip = addr[0]

                        if ip in seen_ips:
                            continue
                        seen_ips.add(ip)

                        # Parse response
                        device_info = self._parse_nbstat_response(data, ip)
                        if device_info:
                            with self._lock:
                                self.discovered_devices[ip] = device_info
                                logger.debug(f"NetBIOS: Found {ip} - {device_info.name}")

                    except TimeoutError:
                        continue
                    except Exception as e:
                        logger.debug(f"NetBIOS receive error: {e}")
            finally:
                sock.close()

        except Exception as e:
            logger.warning(f"NetBIOS discovery failed: {e}")

        return self.discovered_devices

    def _build_nbstat_query(self) -> bytes:
        """Build NetBIOS Node Status query for wildcard name using Scapy layers"""
        import random
        from scapy.layers.netbios import NBNSHeader, NBNSQueryRequest

        query = NBNSHeader(
            NAME_TRN_ID=random.randint(0, 0xFFFF),
            OPCODE=0,
            NM_FLAGS=0,
            QDCOUNT=1,
        ) / NBNSQueryRequest(
            QUESTION_NAME="*",
            QUESTION_TYPE=0x0021,  # NBSTAT
            QUESTION_CLASS=0x0001,  # IN
        )
        return bytes(query)

    def _parse_nbstat_response(self, data: bytes, ip: str) -> Optional[DiscoveredDevice]:
        """Parse NetBIOS Node Status response"""
        try:
            if len(data) < 57:  # Minimum valid response
                return None

            # Skip header (12 bytes) and question echo
            offset = 12

            # Skip question section (find the null terminator)
            while offset < len(data) and data[offset] != 0:
                offset += data[offset] + 1
            offset += 1  # Skip null
            offset += 4  # Skip QTYPE and QCLASS

            # Answer section
            if offset + 12 > len(data):
                return None

            # Skip answer name, type, class, ttl, rdlength
            while offset < len(data) and data[offset] != 0:
                offset += data[offset] + 1
            offset += 1  # Skip null
            offset += 10  # Skip type(2) + class(2) + ttl(4) + rdlength(2)

            if offset >= len(data):
                return None

            # Number of names
            num_names = data[offset]
            offset += 1

            names = []
            services = []
            workgroup = None
            computer_name = None

            for _ in range(num_names):
                if offset + 18 > len(data):
                    break

                # Name (15 bytes) + suffix (1 byte) + flags (2 bytes)
                name_bytes = data[offset : offset + 15]
                suffix = data[offset + 15]
                flags = struct.unpack(">H", data[offset + 16 : offset + 18])[0]
                offset += 18

                try:
                    name = name_bytes.decode("ascii").strip()
                except UnicodeDecodeError:
                    name = name_bytes.hex()

                is_group = (flags & 0x8000) != 0
                suffix_desc = self.SUFFIX_TYPES.get(suffix, f"Unknown (0x{suffix:02X})")

                names.append(
                    {
                        "name": name,
                        "suffix": suffix,
                        "suffix_desc": suffix_desc,
                        "is_group": is_group,
                    }
                )

                # Extract computer name (suffix 0x00, not group)
                if suffix == 0x00 and not is_group and not computer_name:
                    computer_name = name

                # Extract workgroup/domain (suffix 0x00, group)
                if suffix == 0x00 and is_group:
                    workgroup = name

                # Track services
                if suffix in [0x20, 0x03, 0x1B, 0x1C, 0x1D]:
                    services.append(suffix_desc)

            # Extract MAC address (6 bytes after names)
            mac_address = None
            if offset + 6 <= len(data):
                mac_bytes = data[offset : offset + 6]
                mac_address = ":".join(f"{b:02x}" for b in mac_bytes)

            return DiscoveredDevice(
                ip_addresses=[ip],
                mac_address=mac_address,
                name=computer_name or f"NetBIOS Host ({ip})",
                device_type="Windows/SMB Host",
                discovered_by=["netbios"],
                first_seen=datetime.now().isoformat(),
                last_seen=datetime.now().isoformat(),
                netbios_data={
                    "computer_name": computer_name,
                    "workgroup": workgroup,
                    "names": names,
                    "services": services,
                    "mac_address": mac_address,
                },
            )

        except Exception as e:
            logger.debug(f"NetBIOS parse error for {ip}: {e}")
            return None


class NetBIOSPassiveListener:
    """Passive NetBIOS traffic listener.

    Listens for NetBIOS broadcasts on UDP 137/138 to discover:
    - Windows hosts via name registrations
    - Workgroups and domains
    - Browser announcements and elections
    - File servers and domain controllers

    NetBIOS uses:
    - UDP 137: Name Service (NBNS) - name registrations, queries
    - UDP 138: Datagram Service (NBDS) - browser announcements

    Usage:
        # Live capture
        listener = NetBIOSPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()

        # Testing - feed packets directly
        listener = NetBIOSPassiveListener(interface="eth0")
        listener.feed_packet(mock_netbios_packet)
    """

    PROTOCOL_NAME = "netbios-passive"
    BPF_FILTER = "udp port 137 or udp port 138"

    NETBIOS_NS_PORT = 137
    NETBIOS_DGM_PORT = 138

    # NetBIOS suffix types (same as NetBIOSScanner)
    SUFFIX_TYPES = {
        0x00: "Workstation",
        0x03: "Messenger Service",
        0x06: "RAS Server",
        0x1B: "Domain Master Browser",
        0x1C: "Domain Controllers",
        0x1D: "Master Browser",
        0x1E: "Browser Service Elections",
        0x1F: "NetDDE Service",
        0x20: "File Server",
        0x21: "RAS Client",
        0x22: "Exchange Interchange",
        0x23: "Exchange Store",
        0x24: "Exchange Directory",
        0x30: "Modem Sharing Server",
        0x31: "Modem Sharing Client",
        0x43: "SMS Clients Remote Control",
        0x44: "SMS Admin Remote Control Tool",
        0x45: "SMS Clients Remote Chat",
        0x46: "SMS Clients Remote Transfer",
        0x87: "Exchange MTA",
        0xBE: "Network Monitor Agent",
        0xBF: "Network Monitor Application",
    }

    # NetBIOS Name Service opcodes
    NB_OPCODES = {
        0: "Query",
        5: "Registration",
        6: "Release",
        7: "WACK",
        8: "Refresh",
    }

    # Browser command types (for NBDS port 138)
    BROWSER_COMMANDS = {
        0x01: "Host Announcement",
        0x02: "Request Announcement",
        0x08: "Browser Election",
        0x09: "Get Backup List Request",
        0x0A: "Get Backup List Response",
        0x0B: "Become Backup Browser",
        0x0C: "Domain/Workgroup Announcement",
        0x0D: "Master Announcement",
        0x0E: "Reset State",
        0x0F: "Local Master Announcement",
    }

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
    ):
        self.interface = validate_interface(interface)
        self.timeout = validate_timeout(timeout)
        self.discovered_devices: Dict[str, DiscoveredDevice] = {}
        self.workgroups: Dict[str, List[str]] = {}  # workgroup -> list of hosts
        self._lock = threading.Lock()

    def scan(self) -> Dict[str, DiscoveredDevice]:
        """Run discovery via live capture."""
        return self._live_capture()

    def _live_capture(self) -> Dict[str, DiscoveredDevice]:
        """Capture NetBIOS from live interface."""
        if not _scapy_all.is_available:
            logger.debug("NetBIOS: scapy not available")
            return {}
        scapy = _scapy_all()
        AsyncSniffer, conf = scapy.AsyncSniffer, scapy.conf

        conf.verb = 0
        logger.debug(f"NetBIOS: Listening on {self.interface} for {self.timeout}s")

        sniffer = AsyncSniffer(
            iface=self.interface,
            filter=self.BPF_FILTER,
            prn=self._safe_process_packet,
            store=False,
        )

        sniffer.start()
        time.sleep(self.timeout)
        sniffer.stop()

        logger.debug(
            f"NetBIOS: {len(self.discovered_devices)} devices, {len(self.workgroups)} workgroups"
        )
        return self.discovered_devices

    def _safe_process_packet(self, packet) -> None:
        """Wrapper with error handling."""
        try:
            self._process_packet(packet)
        except Exception as e:
            logger.debug(f"NetBIOS packet error: {e}")

    def feed_packet(self, packet) -> None:
        """Feed a single packet for testing."""
        self._safe_process_packet(packet)

    def feed_packets(self, packets) -> Dict[str, DiscoveredDevice]:
        """Feed multiple packets and return discovered devices."""
        for pkt in packets:
            self._safe_process_packet(pkt)
        return self.discovered_devices

    def _process_packet(self, packet) -> None:
        """Process captured NetBIOS packet using scapy's native layers."""
        if not _scapy_all.is_available or not _scapy_netbios.is_available:
            return
        scapy = _scapy_all()
        IP, UDP, Ether = scapy.IP, scapy.UDP, scapy.Ether
        nb = _scapy_netbios()
        NBNSHeader = nb.NBNSHeader
        NBNSQueryResponse = nb.NBNSQueryResponse
        NBNSRegistrationRequest = nb.NBNSRegistrationRequest
        NBNSNodeStatusResponse = nb.NBNSNodeStatusResponse
        NBTDatagram = nb.NBTDatagram

        if IP not in packet or UDP not in packet:
            return

        src_ip = packet[IP].src
        dport = packet[UDP].dport
        sport = packet[UDP].sport

        # Extract MAC from Ethernet layer if available
        src_mac = ""
        if Ether in packet:
            src_mac = packet[Ether].src

        # Skip if not NetBIOS ports
        if dport not in [137, 138] and sport not in [137, 138]:
            return

        # Port 137: Name Service - try scapy's native layers
        if dport == 137 or sport == 137:
            if NBNSNodeStatusResponse in packet:
                self._process_node_status_response(packet, src_ip, src_mac)
            elif NBNSQueryResponse in packet:
                self._process_query_response(packet, src_ip, src_mac)
            elif NBNSRegistrationRequest in packet:
                self._process_registration(packet, src_ip, src_mac)
            elif NBNSHeader in packet:
                # Generic NBNS packet - check opcode
                self._process_nbns_header(packet, src_ip)

        # Port 138: Datagram Service
        elif dport == 138 or sport == 138:
            if NBTDatagram in packet:
                self._process_nbt_datagram(packet, src_ip)

    def _process_registration(self, packet, src_ip: str, src_mac: str = "") -> None:
        """Process NBNSRegistrationRequest using scapy's native layer."""
        try:
            from scapy.layers.netbios import NBNSRegistrationRequest

            reg = packet[NBNSRegistrationRequest]
            name = reg.QUESTION_NAME.decode("ascii", errors="ignore").strip()
            suffix = self._decode_scapy_suffix(reg.SUFFIX if hasattr(reg, "SUFFIX") else 0x00)

            self._add_netbios_device(
                src_ip=src_ip,
                src_mac=src_mac,
                name=name,
                suffix=suffix,
                registration=True,
            )

        except Exception as e:
            logger.debug(f"NetBIOS registration parse error: {e}")

    def _process_query_response(self, packet, src_ip: str, src_mac: str = "") -> None:
        """Process NBNSQueryResponse using scapy's native layer."""
        try:
            from scapy.layers.netbios import NBNSQueryResponse

            resp = packet[NBNSQueryResponse]
            name = resp.RR_NAME.decode("ascii", errors="ignore").strip()
            suffix = self._decode_scapy_suffix(resp.SUFFIX if hasattr(resp, "SUFFIX") else 0x00)

            # Extract IP from ADDR_ENTRY if available
            ip_addr = src_ip
            if hasattr(resp, "ADDR_ENTRY") and resp.ADDR_ENTRY:
                for entry in resp.ADDR_ENTRY:
                    if hasattr(entry, "NB_ADDRESS"):
                        ip_addr = str(entry.NB_ADDRESS)
                        break

            self._add_netbios_device(
                src_ip=src_ip,
                src_mac=src_mac,
                name=name,
                suffix=suffix,
                ip_from_response=ip_addr,
            )

        except Exception as e:
            logger.debug(f"NetBIOS query response parse error: {e}")

    def _process_node_status_response(self, packet, src_ip: str, src_mac: str = "") -> None:
        """Process NBNSNodeStatusResponse using scapy's native layer."""
        try:
            from scapy.layers.netbios import NBNSNodeStatusResponse

            resp = packet[NBNSNodeStatusResponse]
            names = []
            computer_name = None
            workgroup = None

            # Parse NODE_NAME entries
            if hasattr(resp, "NODE_NAME") and resp.NODE_NAME:
                for node in resp.NODE_NAME:
                    node_name = node.NETBIOS_NAME.decode("ascii", errors="ignore").strip()
                    suffix = self._decode_scapy_suffix(
                        node.SUFFIX if hasattr(node, "SUFFIX") else 0x00
                    )

                    # Check if group flag is set
                    flags = node.NAME_FLAGS if hasattr(node, "NAME_FLAGS") else 0
                    is_group = bool(flags & 0x8000)

                    suffix_desc = self.SUFFIX_TYPES.get(suffix, f"Unknown (0x{suffix:02X})")

                    names.append(
                        {
                            "name": node_name,
                            "suffix": suffix,
                            "suffix_desc": suffix_desc,
                            "is_group": is_group,
                        }
                    )

                    if suffix == 0x00 and not is_group and not computer_name:
                        computer_name = node_name
                    if suffix == 0x00 and is_group:
                        workgroup = node_name

            # Get MAC address - prefer from protocol, fall back to Ethernet layer
            mac_address = None
            if hasattr(resp, "MAC_ADDRESS") and resp.MAC_ADDRESS:
                mac_address = resp.MAC_ADDRESS
            elif src_mac:
                mac_address = src_mac

            with self._lock:
                # Use MAC as key if available, otherwise fall back to IP
                device_key = mac_address if mac_address else f"netbios:{src_ip}"

                if device_key not in self.discovered_devices:
                    device = DiscoveredDevice(
                        mac_address=mac_address or "",
                        ip_addresses=[src_ip],
                        name=computer_name or f"NetBIOS Host ({src_ip})",
                        manufacturer="",
                        model="",
                        device_type="Windows/SMB Host",
                        discovered_by=["netbios-passive"],
                        first_seen=datetime.now().isoformat(),
                        last_seen=datetime.now().isoformat(),
                    )

                    device.netbios_data = {
                        "computer_name": computer_name,
                        "workgroup": workgroup,
                        "names": names,
                        "mac_address": mac_address,
                    }

                    self.discovered_devices[device_key] = device

                    if workgroup:
                        self.workgroups.setdefault(workgroup, []).append(src_ip)

                    logger.debug(f"NetBIOS: {src_ip} = {computer_name} in {workgroup}")
                else:
                    self.discovered_devices[device_key].last_seen = datetime.now().isoformat()

        except Exception as e:
            logger.debug(f"NetBIOS node status parse error: {e}")

    def _process_nbns_header(self, packet, src_ip: str) -> None:
        """Process generic NBNSHeader for other packet types."""
        try:
            from scapy.layers.netbios import NBNSHeader

            hdr = packet[NBNSHeader]
            opcode = hdr.OPCODE if hasattr(hdr, "OPCODE") else 0
            is_response = hdr.RESPONSE if hasattr(hdr, "RESPONSE") else 0

            # Log for debugging
            logger.debug(f"NetBIOS: {src_ip} NBNS opcode={opcode} response={is_response}")

        except Exception as e:
            logger.debug(f"NetBIOS header parse error: {e}")

    def _add_netbios_device(
        self,
        src_ip: str,
        name: str,
        suffix: int,
        registration: bool = False,
        ip_from_response: Optional[str] = None,
        src_mac: str = "",
    ) -> None:
        """Add or update a NetBIOS device."""
        if not name:
            return

        suffix_desc = self.SUFFIX_TYPES.get(suffix, f"Unknown (0x{suffix:02X})")

        # The NBNS answer record (ADDR_ENTRY.NB_ADDRESS) can advertise an IP
        # that differs from the packet source - e.g. a WINS server answering on
        # behalf of another host - so track both.
        ip_addresses = [src_ip]
        if ip_from_response and ip_from_response not in ip_addresses:
            ip_addresses.append(ip_from_response)

        with self._lock:
            # Use MAC as key if available, otherwise fall back to IP
            device_key = src_mac if src_mac else f"netbios:{src_ip}"

            if device_key not in self.discovered_devices:
                device = DiscoveredDevice(
                    mac_address=src_mac,
                    ip_addresses=ip_addresses,
                    name=name,
                    manufacturer="",
                    model="",
                    device_type="Windows/SMB Host",
                    discovered_by=["netbios-passive"],
                    first_seen=datetime.now().isoformat(),
                    last_seen=datetime.now().isoformat(),
                )

                device.netbios_data = {
                    "computer_name": name if suffix == 0x00 else None,
                    "workgroup": name if suffix == 0x00 else None,
                    "names": [{"name": name, "suffix": suffix, "suffix_desc": suffix_desc}],
                    "services": [suffix_desc] if suffix in [0x20, 0x1B, 0x1C, 0x1D] else [],
                    "registration": registration,
                }

                self.discovered_devices[device_key] = device
                action = "registered" if registration else "found"
                logger.debug(f"NetBIOS: {src_ip} {action} '{name}' ({suffix_desc})")
            else:
                device = self.discovered_devices[device_key]
                device.last_seen = datetime.now().isoformat()
                # Merge any newly observed IPs (e.g. the answer-record address)
                for ip in ip_addresses:
                    if ip and ip not in device.ip_addresses:
                        device.ip_addresses.append(ip)
                # Add new name if not already present
                if device.netbios_data is None:
                    device.netbios_data = {}
                name_entry = {"name": name, "suffix": suffix, "suffix_desc": suffix_desc}
                if name_entry not in device.netbios_data.get("names", []):
                    device.netbios_data.setdefault("names", []).append(name_entry)

    def _process_nbt_datagram(self, packet, src_ip: str) -> None:
        """Process NBTDatagram using scapy's native layer."""
        try:
            from scapy.layers.netbios import NBTDatagram

            dgm = packet[NBTDatagram]

            # Get source and destination names from scapy
            source_name = ""
            if hasattr(dgm, "SourceName") and dgm.SourceName:
                source_name = dgm.SourceName.decode("ascii", errors="ignore").strip()

            dest_name = ""
            if hasattr(dgm, "DestinationName") and dgm.DestinationName:
                dest_name = dgm.DestinationName.decode("ascii", errors="ignore").strip()

            # Get suffix (encoded, needs decoding)
            suffix = self._decode_scapy_suffix(dgm.SUFFIX1 if hasattr(dgm, "SUFFIX1") else 0x00)

            if source_name:
                self._add_netbios_device(
                    src_ip=src_ip,
                    name=source_name,
                    suffix=suffix,
                )

            logger.debug(f"NetBIOS: Datagram from {source_name} to {dest_name} ({src_ip})")

        except Exception as e:
            logger.debug(f"NetBIOS datagram parse error: {e}")

    def _decode_scapy_suffix(self, encoded_suffix) -> int:
        """Decode NetBIOS encoded suffix from scapy.

        Scapy stores the suffix in NetBIOS encoded form where each nibble
        is stored as (nibble + ord('A')). So 0x00 becomes 'AA' (0x4141),
        and 0x20 becomes 'CA' (0x4341).
        """
        if isinstance(encoded_suffix, int):
            if encoded_suffix > 0xFF:
                # Encoded form - decode it
                high = (encoded_suffix >> 8) & 0xFF
                low = encoded_suffix & 0xFF
                return ((high - ord("A")) << 4) | (low - ord("A"))
            # Already decoded (single byte)
            return encoded_suffix
        return 0x00


class STPPassiveListener:
    """STP/RSTP switch discovery via BPDU passive listening.

    Usage:
        # Live capture
        listener = STPPassiveListener(interface="eth0", timeout=30)
        devices = listener.scan()

        # Testing - feed packets directly
        listener = STPPassiveListener(interface="eth0")
        listener.feed_packet(mock_bpdu_packet)
    """

    PROTOCOL_NAME = "stp"
    BPF_FILTER = "ether dst 01:80:c2:00:00:00"

    STP_MULTICAST_MAC = "01:80:c2:00:00:00"

    # STP Protocol versions
    PROTOCOL_VERSIONS = {
        0: "STP (802.1D)",
        2: "RSTP (802.1w)",
        3: "MSTP (802.1s)",
    }

    # BPDU Types
    BPDU_TYPES = {
        0x00: "Configuration BPDU",
        0x02: "RST/MST BPDU",
        0x80: "TCN BPDU",
    }

    def __init__(self, interface: str, timeout: int = 30):
        _scapy_all()  # Ensure scapy is available
        self.interface = validate_interface(interface)

        self.timeout = validate_timeout(timeout)
        self.discovered_devices: Dict[str, DiscoveredDevice] = {}
        self._lock = threading.Lock()

    def scan(self) -> Dict[str, DiscoveredDevice]:
        """Run discovery via live capture."""
        return self._live_capture()

    def _live_capture(self) -> Dict[str, DiscoveredDevice]:
        """Passively listen for STP/RSTP BPDUs."""
        if not _scapy_all.is_available:
            logger.warning("scapy not available, STP discovery disabled")
            return self.discovered_devices
        scapy = _scapy_all()
        AsyncSniffer, conf = scapy.AsyncSniffer, scapy.conf

        conf.verb = 0
        logger.debug(f"STP: Listening for BPDUs on {self.interface} for {self.timeout}s")

        sniffer = None
        try:
            sniffer = AsyncSniffer(
                iface=self.interface,
                filter=self.BPF_FILTER,
                prn=self._safe_process_packet,
                store=False,
            )

            sniffer.start()
            time.sleep(self.timeout)
        except OSError as e:
            logger.debug(f"STP: Interface error: {e}")
        except Exception as e:
            logger.debug(f"STP: Sniffer error: {e}")
        finally:
            if sniffer and sniffer.running:
                try:
                    sniffer.stop()
                except OSError as e:
                    logger.debug(f"STP: sniffer stop error: {e}")

        logger.debug(f"STP: Found {len(self.discovered_devices)} switches")
        return self.discovered_devices

    def _safe_process_packet(self, packet) -> None:
        """Wrapper with error handling for packet processing."""
        try:
            if self.should_process_packet(packet):
                self.process_packet(packet)
        except Exception as e:
            logger.debug(f"STP packet error: {e}")

    def should_process_packet(self, packet) -> bool:
        """Check if packet is an STP BPDU."""
        from scapy.all import Ether
        from scapy.layers.l2 import Dot3

        # Check for Ethernet or 802.3 frame
        if Ether in packet:
            dst = packet[Ether].dst.lower()
        elif Dot3 in packet:
            dst = packet[Dot3].dst.lower()
        else:
            return False
        return dst == self.STP_MULTICAST_MAC.lower()

    def process_packet(self, packet) -> None:
        """Process STP BPDU packet."""
        self._parse_bpdu(packet)

    # Testing API
    def feed_packet(self, packet) -> None:
        """Feed single packet for testing."""
        self._safe_process_packet(packet)

    def feed_packets(self, packets) -> Dict[str, DiscoveredDevice]:
        """Feed multiple packets, return results."""
        for pkt in packets:
            self._safe_process_packet(pkt)
        return self.discovered_devices

    def _parse_bpdu(self, packet) -> None:
        """Parse STP/RSTP BPDU frame using Scapy's STP layer fields"""
        try:
            from scapy.all import LLC, STP, Raw

            # Check packet has source MAC
            if not hasattr(packet, "src"):
                return

            # Check for LLC header (DSAP/SSAP = 0x42)
            if not packet.haslayer(LLC):
                return

            llc = packet[LLC]
            if llc.dsap != 0x42 or llc.ssap != 0x42:
                return

            # Prefer Scapy's native STP layer for parsed field access
            if packet.haslayer(STP):
                stp = packet[STP]
            elif packet.haslayer(Raw):
                # Try to dissect raw payload as STP
                try:
                    stp = STP(bytes(packet[Raw].load))
                except Exception as e:
                    logger.debug(f"STP: Raw payload dissection failed: {e}")
                    return
            else:
                return

            # Validate STP protocol ID
            if stp.proto != 0x0000:
                return

            version = stp.version
            bpdu_type = stp.bpdutype

            protocol_name = self.PROTOCOL_VERSIONS.get(version, f"Unknown ({version})")

            # Parse Configuration BPDU (type 0x00 or 0x02)
            if bpdu_type in [0x00, 0x02]:
                flags = stp.bpduflags
                root_priority = stp.rootid
                root_mac = stp.rootmac
                root_path_cost = stp.pathcost
                bridge_priority = stp.bridgeid
                bridge_mac = stp.bridgemac
                port_id = stp.portid

                # Scapy returns timers as float seconds (already divided by 256)
                message_age = stp.age
                max_age = stp.maxage
                hello_time = stp.hellotime
                forward_delay = stp.fwddelay

                # RSTP-specific port role extraction from flags
                is_root = root_mac == bridge_mac
                port_role = None
                if version >= 2:  # RSTP
                    role_bits = (flags >> 2) & 0x03
                    roles = {0: "Unknown", 1: "Alternate/Backup", 2: "Root", 3: "Designated"}
                    port_role = roles.get(role_bits, "Unknown")

                # Use bridge MAC as device identifier
                device_key = bridge_mac

                with self._lock:
                    if device_key not in self.discovered_devices:
                        self.discovered_devices[device_key] = DiscoveredDevice(
                            mac_address=bridge_mac,
                            name=f"Switch ({bridge_mac})",
                            device_type="Network Switch",
                            discovered_by=["stp"],
                            first_seen=datetime.now().isoformat(),
                            last_seen=datetime.now().isoformat(),
                            stp_data={
                                "protocol": protocol_name,
                                "version": version,
                                "bridge_mac": bridge_mac,
                                "bridge_priority": bridge_priority,
                                "root_mac": root_mac,
                                "root_priority": root_priority,
                                "root_path_cost": root_path_cost,
                                "is_root_bridge": is_root,
                                "port_id": port_id,
                                "port_role": port_role,
                                "timers": {
                                    "hello_time": hello_time,
                                    "max_age": max_age,
                                    "forward_delay": forward_delay,
                                    "message_age": message_age,
                                },
                            },
                        )
                        logger.debug(f"STP: Found switch {bridge_mac} ({protocol_name})")
                    else:
                        # Update last seen
                        self.discovered_devices[device_key].last_seen = datetime.now().isoformat()

        except Exception as e:
            logger.debug(f"STP BPDU parse error: {e}")
