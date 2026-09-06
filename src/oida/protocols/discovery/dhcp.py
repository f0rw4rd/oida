"""
DHCP-based discovery scanners.

Contains:
- DHCPPassiveListener: Passive DHCP traffic monitoring
- DHCPServerScanner: Active DHCP server discovery
"""

import random
import threading
import time
from datetime import datetime
from typing import Dict, Set

from .core import (
    DiscoveredDevice,
    compute_network_cidr,
    get_interface_networks,
    is_valid_discovered_ip,
    is_valid_mac,
    lookup_mac_vendor,
    normalize_mac,
    validate_interface,
    validate_timeout,
)
from ...utils.ics_logger import get_module_logger

logger = get_module_logger(__name__)

# DHCP ports
DHCP_CLIENT_PORT = 68
DHCP_SERVER_PORT = 67

# DHCP message types
DHCP_DISCOVER = 1
DHCP_OFFER = 2
DHCP_REQUEST = 3
DHCP_DECLINE = 4
DHCP_ACK = 5
DHCP_NAK = 6
DHCP_RELEASE = 7
DHCP_INFORM = 8

DHCP_MSG_NAMES = {
    1: "DISCOVER",
    2: "OFFER",
    3: "REQUEST",
    4: "DECLINE",
    5: "ACK",
    6: "NAK",
    7: "RELEASE",
    8: "INFORM",
}


class DHCPPassiveListener:
    """Passive DHCP traffic listener.

    Captures DHCP Discover/Request/ACK to identify:
    - New devices joining the network
    - Device hostnames and vendor classes
    - DHCP servers

    Usage:
        # Live capture
        listener = DHCPPassiveListener(interface="eth0", timeout=30)
        devices = listener.scan()

        # Testing - feed packets directly
        listener = DHCPPassiveListener(interface="eth0")
        listener.feed_packet(mock_dhcp_packet)
    """

    PROTOCOL_NAME = "dhcp-passive"
    BPF_FILTER = "udp and (port 67 or port 68)"

    def __init__(
        self,
        interface: str,
        timeout: int = 30,
        nxc_logger=None,
    ):
        self.interface = validate_interface(interface)

        self.timeout = validate_timeout(timeout)
        self.discovered_devices: Dict[str, DiscoveredDevice] = {}
        self.dhcp_servers: Set[str] = set()
        self._lock = threading.Lock()
        self.nxc_logger = nxc_logger  # NXC-style logger for colored output

    def scan(self) -> Dict[str, DiscoveredDevice]:
        """Run discovery via live capture."""
        return self._live_capture()

    def _live_capture(self) -> Dict[str, DiscoveredDevice]:
        """Passively listen for DHCP traffic."""
        from scapy.all import AsyncSniffer, conf

        conf.verb = 0
        logger.debug(f"DHCP passive: Listening on {self.interface} for {self.timeout}s")

        sniffer = AsyncSniffer(
            iface=self.interface,
            filter=self.BPF_FILTER,
            prn=self._safe_process_packet,
            store=False,
        )

        try:
            sniffer.start()
            time.sleep(self.timeout)
        finally:
            try:
                sniffer.stop()
            except OSError as e:
                logger.debug(f"DHCP: Sniffer stop error: {e}")

        logger.debug(
            f"DHCP passive: {len(self.discovered_devices)} clients, "
            f"{len(self.dhcp_servers)} servers detected"
        )
        return self.discovered_devices

    def _safe_process_packet(self, packet) -> None:
        """Wrapper with error handling for packet processing."""
        try:
            if self.should_process_packet(packet):
                self.process_packet(packet)
        except Exception as e:
            logger.debug(f"DHCP packet parse error: {e}")

    def should_process_packet(self, packet) -> bool:
        """Check if packet is a DHCP packet."""
        from scapy.all import DHCP

        return DHCP in packet

    def process_packet(self, packet) -> None:
        """Process DHCP packet (alias for _process_dhcp)."""
        self._process_dhcp(packet)

    # Testing API
    def feed_packet(self, packet) -> None:
        """Feed single packet for testing."""
        self._safe_process_packet(packet)

    def feed_packets(self, packets) -> Dict[str, DiscoveredDevice]:
        """Feed multiple packets, return results."""
        for pkt in packets:
            self._safe_process_packet(pkt)
        return self.discovered_devices

    def _process_dhcp(self, packet) -> None:
        """Process DHCP packet and extract device info."""
        from scapy.all import BOOTP, DHCP

        try:
            bootp = packet[BOOTP]
            dhcp = packet[DHCP]

            # Get client MAC from BOOTP header
            client_mac = normalize_mac(bootp.chaddr[:6].hex(":"))
            if not is_valid_mac(client_mac):
                return

            # Parse DHCP options
            options = self._parse_dhcp_options(dhcp.options)
            msg_type = options.get("message-type", 0)

            if msg_type in (DHCP_DISCOVER, DHCP_REQUEST, DHCP_INFORM):
                # Client traffic - extract device info
                self._process_client(packet, client_mac, options, msg_type)

            elif msg_type in (DHCP_OFFER, DHCP_ACK):
                # Server traffic - track server and update client
                self._process_server_response(packet, client_mac, options)

        except Exception as e:
            logger.debug(f"DHCP parse error: {e}")

    def _process_client(self, packet, client_mac: str, options: Dict, msg_type: int) -> None:
        """Process DHCP client message (Discover/Request/Inform)."""
        with self._lock:
            hostname = options.get("hostname", "")
            vendor_class = options.get("vendor_class_id", "")
            requested_ip = options.get("requested_addr", "")
            param_list = options.get("param_req_list", [])
            client_id_raw = options.get("client_id", None)

            # Decode bytes if needed
            if isinstance(hostname, bytes):
                hostname = hostname.decode("utf-8", errors="ignore")
            if isinstance(vendor_class, bytes):
                vendor_class = vendor_class.decode("utf-8", errors="ignore")

            # Parse client ID (option 61)
            client_id = ""
            client_id_type = ""
            if client_id_raw:
                client_id, client_id_type = self._parse_client_id(client_id_raw)

            # Build discovery reason
            msg_name = DHCP_MSG_NAMES.get(msg_type, str(msg_type))
            reason = f"dhcp:{msg_name}"

            if client_mac in self.discovered_devices:
                device = self.discovered_devices[client_mac]
                device.last_seen = datetime.now().isoformat()
                # Update hostname if we got a new one
                if hostname and not device.name:
                    device.name = hostname
                # Add discovery reason if not already present
                if reason not in device.discovery_reasons:
                    device.discovery_reasons.append(reason)
                # Update client_id if we got one
                if client_id and device.dhcp_data:
                    device.dhcp_data["client_id"] = client_id
                    device.dhcp_data["client_id_type"] = client_id_type
            else:
                vendor = lookup_mac_vendor(client_mac)
                device = DiscoveredDevice(
                    mac_address=client_mac,
                    ip_addresses=[requested_ip] if requested_ip else [],
                    name=hostname,
                    manufacturer=vendor if vendor != "Unknown" else "",
                    discovered_by=["dhcp-passive"],
                    discovery_reasons=[reason],
                    first_seen=datetime.now().isoformat(),
                    last_seen=datetime.now().isoformat(),
                    dhcp_data={
                        "hostname": hostname,
                        "vendor_class": vendor_class,
                        "requested_ip": requested_ip,
                        "param_request_list": param_list,
                        "message_type": msg_name,
                        "client_id": client_id,
                        "client_id_type": client_id_type,
                    },
                )
                self.discovered_devices[client_mac] = device
                client_id_info = f" client_id={client_id}" if client_id else ""
                logger.debug(
                    f"DHCP: {client_mac} {msg_name} "
                    f"hostname={hostname} vendor={vendor_class}{client_id_info}"
                )

    def _process_server_response(self, packet, client_mac: str, options: Dict) -> None:
        """Process DHCP server response (Offer/ACK)."""
        from scapy.all import BOOTP, IP

        bootp = packet[BOOTP]
        ip_layer = packet[IP] if IP in packet else None

        # Server IP from DHCP option 54 or IP source
        server_ip = options.get("server_id", "")
        if not server_ip and ip_layer:
            server_ip = ip_layer.src

        # Offered/assigned IP
        offered_ip = bootp.yiaddr
        if offered_ip == "0.0.0.0":
            offered_ip = ""

        # Check for network mismatch (rogue DHCP detection)
        subnet_mask = options.get("subnet_mask", "")
        if subnet_mask and offered_ip:
            self._check_network_mismatch(offered_ip, subnet_mask, server_ip)

        with self._lock:
            # Track DHCP server (validate IP)
            if server_ip and is_valid_discovered_ip(server_ip, self.interface):
                if server_ip not in self.dhcp_servers:
                    self.dhcp_servers.add(server_ip)
                    logger.debug(f"DHCP: Server detected at {server_ip}")

                # Also add server as discovered device
                if server_ip not in [
                    d.ip_addresses[0] for d in self.discovered_devices.values() if d.ip_addresses
                ]:
                    server_device = DiscoveredDevice(
                        mac_address="",
                        ip_addresses=[server_ip],
                        name="",
                        device_type="DHCP Server",
                        discovered_by=["dhcp-passive"],
                        first_seen=datetime.now().isoformat(),
                        last_seen=datetime.now().isoformat(),
                        dhcp_data={
                            "is_server": True,
                            "server_ip": server_ip,
                        },
                    )
                    self.discovered_devices[f"ip:{server_ip}"] = server_device

            # Update client with assigned IP
            if client_mac in self.discovered_devices and offered_ip:
                device = self.discovered_devices[client_mac]
                if offered_ip not in device.ip_addresses:
                    device.ip_addresses.append(offered_ip)
                device.last_seen = datetime.now().isoformat()
                if device.dhcp_data:
                    device.dhcp_data["assigned_ip"] = offered_ip
                    device.dhcp_data["dhcp_server"] = server_ip

    def _parse_dhcp_options(self, options) -> Dict:
        """Parse DHCP options into a dictionary."""
        result = {}
        for opt in options:
            if isinstance(opt, tuple) and len(opt) >= 2:
                name, value = opt[0], opt[1]
                result[name] = value
            elif opt == "end":
                break
        return result

    def _parse_client_id(self, client_id_raw) -> tuple:
        """Parse DHCP client ID (option 61).

        Returns:
            tuple: (client_id_string, type_string)

        Client ID format:
        - Type 1 (Ethernet): First byte = 0x01, followed by MAC address
        - Type 0 or other: Arbitrary identifier (hostname, FQDN, GUID, etc.)
        """
        try:
            if isinstance(client_id_raw, bytes):
                data = client_id_raw
            elif isinstance(client_id_raw, str):
                return (client_id_raw, "string")
            else:
                return ("", "")

            if len(data) < 2:
                return ("", "")

            hw_type = data[0]

            if hw_type == 1 and len(data) >= 7:
                # Ethernet hardware address (type 1)
                mac = ":".join(f"{b:02x}" for b in data[1:7])
                return (mac, "mac")
            elif hw_type == 0:
                # String identifier
                try:
                    return (data[1:].decode("utf-8", errors="ignore").rstrip("\x00"), "string")
                except Exception:
                    return (data[1:].hex(), "hex")
            elif hw_type == 255:
                # GUID/UUID (common in Windows)
                if len(data) >= 17:
                    # Format as GUID
                    guid_bytes = data[1:17]
                    guid = (
                        f"{guid_bytes[0:4].hex()}-{guid_bytes[4:6].hex()}-"
                        f"{guid_bytes[6:8].hex()}-{guid_bytes[8:10].hex()}-"
                        f"{guid_bytes[10:16].hex()}"
                    )
                    return (guid, "guid")
                return (data[1:].hex(), "guid")
            else:
                # Other hardware type or unknown format
                # Try to decode as string, fallback to hex
                try:
                    decoded = data[1:].decode("utf-8", errors="ignore").rstrip("\x00")
                    if decoded.isprintable() and len(decoded) > 0:
                        return (decoded, f"type{hw_type}")
                except Exception as e:
                    logger.debug(f"DHCP: client_id UTF-8 decode failed: {e}")
                return (data[1:].hex(), f"type{hw_type}")

        except Exception as e:
            logger.debug(f"DHCP: client_id parse error: {e}")
            return ("", "")

    def _check_network_mismatch(self, offered_ip: str, subnet_mask: str, server_ip: str) -> None:
        """Check if DHCP offer network differs from local interface network.

        Args:
            offered_ip: IP address offered by DHCP server
            subnet_mask: Subnet mask from DHCP offer
            server_ip: DHCP server IP for logging
        """
        offered_network = compute_network_cidr(offered_ip, subnet_mask)
        if not offered_network:
            return

        local_networks = get_interface_networks(self.interface)
        local_cidrs = [cidr for _, cidr in local_networks]

        if not local_cidrs:
            # No local networks to compare against
            return

        if offered_network not in local_cidrs:
            msg = (
                f"DHCP offer network {offered_network} differs from "
                f"local network(s) {', '.join(local_cidrs)}"
            )
            if self.nxc_logger:
                self.nxc_logger.warning(msg)
            else:
                logger.warning(msg)


class DHCPServerScanner:
    """Active DHCP server discovery.

    Sends DHCP Discover to find all DHCP servers on the network.
    Useful for detecting rogue DHCP servers.
    """

    def __init__(self, interface: str, timeout: float = 5.0, nxc_logger=None):
        self.interface = validate_interface(interface)
        self.timeout = validate_timeout(timeout)
        self.servers: Dict[str, DiscoveredDevice] = {}
        self._lock = threading.Lock()
        self._xid = random.randint(1, 0xFFFFFFFF)
        self.nxc_logger = nxc_logger  # NXC-style logger for colored output

    def scan(self) -> Dict[str, DiscoveredDevice]:
        """Send DHCP Discover and collect all server responses."""
        from scapy.all import (
            BOOTP,
            DHCP,
            UDP,
            IP,
            Ether,
            AsyncSniffer,
            conf,
            get_if_hwaddr,
        )
        from ...utils.rate_limiter import scapy_sendp

        conf.verb = 0

        try:
            local_mac = get_if_hwaddr(self.interface)
        except (OSError, RuntimeError) as e:
            logger.debug(f"DHCP: Could not get MAC for {self.interface}: {e}")
            local_mac = "00:00:00:00:00:00"

        logger.debug(f"DHCP server scan: Sending Discover on {self.interface}")

        # Build DHCP Discover packet
        discover = (
            Ether(src=local_mac, dst="ff:ff:ff:ff:ff:ff")
            / IP(src="0.0.0.0", dst="255.255.255.255")
            / UDP(sport=68, dport=67)
            / BOOTP(
                chaddr=bytes.fromhex(local_mac.replace(":", "")),
                xid=self._xid,
            )
            / DHCP(options=[("message-type", "discover"), "end"])
        )

        # Start sniffer before sending
        responses = []

        def handle_response(packet):
            try:
                if DHCP in packet and BOOTP in packet:
                    bootp = packet[BOOTP]
                    # Check transaction ID matches
                    if bootp.xid == self._xid:
                        options = self._parse_dhcp_options(packet[DHCP].options)
                        msg_type = options.get("message-type", 0)
                        if msg_type == DHCP_OFFER:
                            responses.append(packet)
            except Exception as e:
                logger.debug(f"DHCP response parse error: {e}")

        sniffer = AsyncSniffer(
            iface=self.interface,
            filter="udp and port 68",
            prn=handle_response,
            store=False,
        )

        sniffer.start()

        # Send discover packet (rate-limited)
        scapy_sendp(discover, iface=self.interface, verbose=False)

        # Wait for responses
        time.sleep(self.timeout)
        sniffer.stop()

        # Process collected responses
        for packet in responses:
            self._process_offer(packet)

        logger.debug(f"DHCP server scan: Found {len(self.servers)} servers")
        return self.servers

    def _process_offer(self, packet) -> None:
        """Process DHCP Offer from a server."""
        from scapy.all import BOOTP, DHCP, IP, Ether

        try:
            bootp = packet[BOOTP]
            ip_layer = packet[IP] if IP in packet else None
            dhcp = packet[DHCP]

            options = self._parse_dhcp_options(dhcp.options)

            # Server IP
            server_ip = options.get("server_id", "")
            if not server_ip and ip_layer:
                server_ip = ip_layer.src

            if not server_ip or server_ip == "0.0.0.0":
                return

            # Server MAC from Ethernet layer
            server_mac = ""
            if Ether in packet:
                server_mac = packet[Ether].src

            # Offered IP
            offered_ip = bootp.yiaddr

            # Basic network config
            lease_time = options.get("lease_time", 0)
            subnet_mask = options.get("subnet_mask", "")
            broadcast_address = options.get("broadcast_address", "")

            # Router/Gateway
            router = self._get_first_ip(options.get("router", ""))

            # DNS servers (option 6)
            dns_servers = self._normalize_ip_list(options.get("name_server", []))

            # Domain name (option 15)
            domain = self._decode_string(options.get("domain", ""))

            # NTP servers (option 42)
            ntp_servers = self._normalize_ip_list(options.get("NTP_server", []))

            # WINS/NetBIOS servers (option 44)
            wins_servers = self._normalize_ip_list(options.get("NetBIOS_server", []))
            netbios_node_type = options.get("NetBIOS_node_type", 0)

            # Time servers - RFC 868 (option 4)
            time_servers = self._normalize_ip_list(options.get("time_server", []))

            # Log/Syslog servers (option 7)
            log_servers = self._normalize_ip_list(options.get("log_server", []))

            # TFTP/PXE boot (options 66, 150, and BOOTP fields)
            tftp_server = self._get_first_ip(options.get("tftp_server_address", ""))
            if not tftp_server:
                tftp_server = self._get_first_ip(options.get("tftp_server_ip_address", ""))
            bootfile = ""
            if bootp.file:
                bootfile = bootp.file.rstrip(b"\x00").decode("utf-8", errors="ignore")
            next_server = bootp.siaddr if bootp.siaddr != "0.0.0.0" else ""
            # Server name from BOOTP header
            server_name = ""
            if bootp.sname:
                server_name = bootp.sname.rstrip(b"\x00").decode("utf-8", errors="ignore")

            # Vendor info (options 43, 60)
            vendor_class = self._decode_string(options.get("vendor_class_id", ""))
            vendor_specific = options.get("vendor_specific", b"")

            # Lease timers
            renewal_time = options.get("renewal_time", 0)  # T1
            rebinding_time = options.get("rebinding_time", 0)  # T2

            # Static routes (option 121 - classless)
            static_routes = options.get("classless_static_routes", [])

            # NIS (options 40, 41)
            nis_domain = self._decode_string(options.get("NIS_domain", ""))
            nis_servers = self._normalize_ip_list(options.get("NIS_server", []))

            # Check for network mismatch (rogue DHCP detection)
            if subnet_mask and offered_ip:
                self._check_network_mismatch(offered_ip, subnet_mask, server_ip)

            with self._lock:
                if server_ip not in self.servers:
                    vendor = lookup_mac_vendor(server_mac) if server_mac else ""

                    # Build dhcp_data dict, excluding None/empty values
                    dhcp_data = {
                        "is_server": True,
                        "server_ip": server_ip,
                        "offered_ip": offered_ip,
                        # Lease info
                        "lease_time": lease_time,
                        "subnet_mask": subnet_mask,
                        "router": router,
                        "dns_servers": dns_servers,
                    }

                    # Add optional fields only if they have values
                    if renewal_time:
                        dhcp_data["renewal_time"] = renewal_time
                    if rebinding_time:
                        dhcp_data["rebinding_time"] = rebinding_time
                    if broadcast_address:
                        dhcp_data["broadcast_address"] = broadcast_address
                    if static_routes:
                        dhcp_data["static_routes"] = static_routes
                    if domain:
                        dhcp_data["domain"] = domain
                    if ntp_servers:
                        dhcp_data["ntp_servers"] = ntp_servers
                    if wins_servers:
                        dhcp_data["wins_servers"] = wins_servers
                    if netbios_node_type:
                        dhcp_data["netbios_node_type"] = netbios_node_type
                    if time_servers:
                        dhcp_data["time_servers"] = time_servers
                    if log_servers:
                        dhcp_data["log_servers"] = log_servers
                    if nis_domain:
                        dhcp_data["nis_domain"] = nis_domain
                    if nis_servers:
                        dhcp_data["nis_servers"] = nis_servers
                    if tftp_server:
                        dhcp_data["tftp_server"] = tftp_server
                    if next_server:
                        dhcp_data["next_server"] = next_server
                    if bootfile:
                        dhcp_data["bootfile"] = bootfile
                    if server_name:
                        dhcp_data["server_name"] = server_name
                    if vendor_class:
                        dhcp_data["vendor_class"] = vendor_class
                    if vendor_specific:
                        dhcp_data["vendor_specific"] = (
                            vendor_specific.hex()
                            if isinstance(vendor_specific, bytes)
                            else str(vendor_specific)
                        )

                    device = DiscoveredDevice(
                        mac_address=server_mac,
                        ip_addresses=[server_ip],
                        name=server_name if server_name else "",
                        manufacturer=vendor if vendor != "Unknown" else "",
                        device_type="DHCP Server",
                        discovered_by=["dhcp-servers"],
                        first_seen=datetime.now().isoformat(),
                        last_seen=datetime.now().isoformat(),
                        dhcp_data=dhcp_data,
                    )
                    self.servers[server_ip] = device

                    # Log discovery using NXC logger if available
                    def log_success(msg):
                        if self.nxc_logger:
                            self.nxc_logger.success(msg)
                        else:
                            logger.info(msg)

                    log_success(f"DHCP Server: {server_ip} (MAC: {server_mac})")
                    log_success(f"  Offered IP: {offered_ip}, Lease: {lease_time}s")

                    # Log network config
                    if subnet_mask:
                        log_success(f"  Subnet: {subnet_mask}")
                    if router:
                        log_success(f"  Gateway: {router}")
                    if dns_servers:
                        log_success(f"  DNS: {', '.join(dns_servers)}")
                    if domain:
                        log_success(f"  Domain: {domain}")

                    # Log name services
                    if ntp_servers:
                        log_success(f"  NTP: {', '.join(ntp_servers)}")
                    if wins_servers:
                        log_success(f"  WINS: {', '.join(wins_servers)}")
                    if time_servers:
                        log_success(f"  Time: {', '.join(time_servers)}")
                    if log_servers:
                        log_success(f"  Syslog: {', '.join(log_servers)}")

                    # Log NIS
                    if nis_domain or nis_servers:
                        nis_info = []
                        if nis_domain:
                            nis_info.append(f"domain={nis_domain}")
                        if nis_servers:
                            nis_info.append(f"servers={', '.join(nis_servers)}")
                        log_success(f"  NIS: {' '.join(nis_info)}")

                    # Log boot/PXE
                    if tftp_server or next_server or bootfile:
                        boot_info = []
                        if tftp_server:
                            boot_info.append(f"tftp={tftp_server}")
                        elif next_server:
                            boot_info.append(f"next-server={next_server}")
                        if bootfile:
                            boot_info.append(f"file={bootfile}")
                        log_success(f"  PXE/Boot: {' '.join(boot_info)}")

                    # Log vendor info
                    if vendor_class:
                        log_success(f"  Vendor: {vendor_class}")

        except Exception as e:
            logger.debug(f"DHCP offer parse error: {e}")

    def _normalize_ip_list(self, value) -> list:
        """Normalize IP list from DHCP option value."""
        if not value:
            return []
        if isinstance(value, list):
            return [str(ip) for ip in value]
        return [str(value)]

    def _get_first_ip(self, value) -> str:
        """Get first IP from option value."""
        if not value:
            return ""
        if isinstance(value, list) and value:
            return str(value[0])
        return str(value)

    def _decode_string(self, value) -> str:
        """Decode string from DHCP option value."""
        if not value:
            return ""
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="ignore").rstrip("\x00")
        return str(value)

    def _parse_dhcp_options(self, options) -> Dict:
        """Parse DHCP options into a dictionary."""
        result = {}
        for opt in options:
            if isinstance(opt, tuple) and len(opt) >= 2:
                name, value = opt[0], opt[1]
                result[name] = value
            elif opt == "end":
                break
        return result

    def _check_network_mismatch(self, offered_ip: str, subnet_mask: str, server_ip: str) -> None:
        """Check if DHCP offer network differs from local interface network.

        Warns if the offered network doesn't match any of the local interface's
        configured networks. This can indicate a rogue or misconfigured DHCP server.

        Args:
            offered_ip: IP address offered by DHCP server
            subnet_mask: Subnet mask from DHCP offer
            server_ip: DHCP server IP for logging
        """
        offered_network = compute_network_cidr(offered_ip, subnet_mask)
        if not offered_network:
            return

        local_networks = get_interface_networks(self.interface)
        local_cidrs = [cidr for _, cidr in local_networks]

        if not local_cidrs:
            # No local networks to compare against
            return

        if offered_network not in local_cidrs:
            msg = (
                f"DHCP offer network {offered_network} differs from "
                f"local network(s) {', '.join(local_cidrs)}"
            )
            if self.nxc_logger:
                self.nxc_logger.warning(msg)
            else:
                logger.warning(msg)
