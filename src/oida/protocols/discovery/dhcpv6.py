"""
DHCPv6 discovery scanners.

DHCPv6 uses:
- UDP port 546 (client)
- UDP port 547 (server/relay)
- Multicast ff02::1:2 (all DHCP agents)

DHCPv6 message types:
1: Solicit, 2: Advertise, 3: Request, 4: Confirm, 5: Renew, 6: Rebind,
7: Reply, 8: Release, 9: Decline, 10: Reconfigure, 11: Information-Request,
12: Relay-Forward, 13: Relay-Reply

Useful for discovering:
- IPv6-enabled devices
- DHCPv6 servers
- Device DUIDs (unique identifiers)
- Vendor class information
"""

import struct
import threading
import time
from datetime import datetime
from typing import Dict, Optional

from .core import (
    DiscoveredDevice,
    validate_interface,
    validate_timeout,
)
from ...utils.rate_limiter import scapy_sendp
from ...utils.ics_logger import get_module_logger
from ...utils.lazy_import import lazy_import

_scapy_all = lazy_import("scapy.all", "discovery")
_scapy_dhcp6 = lazy_import("scapy.layers.dhcp6", "discovery")

logger = get_module_logger(__name__)

# DHCPv6 constants
DHCPV6_CLIENT_PORT = 546
DHCPV6_SERVER_PORT = 547
DHCPV6_MULTICAST_ADDR = "ff02::1:2"  # All DHCP agents

# DHCPv6 message types
DHCPV6_MSG_TYPES = {
    1: "Solicit",
    2: "Advertise",
    3: "Request",
    4: "Confirm",
    5: "Renew",
    6: "Rebind",
    7: "Reply",
    8: "Release",
    9: "Decline",
    10: "Reconfigure",
    11: "Information-Request",
    12: "Relay-Forward",
    13: "Relay-Reply",
}

# DHCPv6 option code (only the one we request in the Solicit)
DHCPV6_OPT_DNS_SERVERS = 23

# DUID types (Device Unique Identifier)
DUID_TYPES = {
    1: "DUID-LLT",  # Link-layer + time
    2: "DUID-EN",  # Enterprise number
    3: "DUID-LL",  # Link-layer only
    4: "DUID-UUID",  # UUID-based
}


class DHCPv6PassiveListener:
    """Passive DHCPv6 traffic listener.

    Captures DHCPv6 messages to identify:
    - IPv6-enabled devices
    - DHCPv6 servers
    - Device DUIDs and vendor classes

    Supports:
    - Live capture via AsyncSniffer
    - Direct packet feeding for testing
    """

    PROTOCOL_NAME = "dhcpv6-passive"
    BPF_FILTER = f"udp port {DHCPV6_CLIENT_PORT} or udp port {DHCPV6_SERVER_PORT}"

    def __init__(
        self,
        interface: str,
        timeout: int = 30,
    ):
        self.interface = validate_interface(interface)
        self.timeout = validate_timeout(timeout)
        self.discovered_devices: Dict[str, DiscoveredDevice] = {}
        self._lock = threading.Lock()

    def scan(self) -> Dict[str, DiscoveredDevice]:
        """Run discovery via live capture."""
        return self._live_capture()

    def _live_capture(self) -> Dict[str, DiscoveredDevice]:
        """Passively listen for DHCPv6 traffic."""
        if not _scapy_all.is_available:
            logger.debug("DHCPv6: scapy not available")
            return {}
        scapy = _scapy_all()
        AsyncSniffer, conf = scapy.AsyncSniffer, scapy.conf

        conf.verb = 0
        logger.debug(f"DHCPv6: Listening on {self.interface} for {self.timeout}s")

        sniffer = AsyncSniffer(
            iface=self.interface,
            filter=self.BPF_FILTER,
            prn=self._safe_process_packet,
            store=False,
        )

        sniffer.start()
        time.sleep(self.timeout)
        sniffer.stop()

        logger.debug(f"DHCPv6: {len(self.discovered_devices)} devices")
        return self.discovered_devices

    def _safe_process_packet(self, packet) -> None:
        """Wrapper with error handling."""
        try:
            from scapy.all import IPv6, UDP

            if IPv6 in packet and UDP in packet:
                sport = packet[UDP].sport
                dport = packet[UDP].dport
                if sport in (DHCPV6_CLIENT_PORT, DHCPV6_SERVER_PORT) or dport in (
                    DHCPV6_CLIENT_PORT,
                    DHCPV6_SERVER_PORT,
                ):
                    self._process_packet(packet)
        except Exception as e:
            logger.debug(f"DHCPv6 packet error: {e}")

    def feed_packet(self, packet) -> None:
        """Feed a single packet for testing."""
        self._safe_process_packet(packet)

    def feed_packets(self, packets) -> Dict[str, DiscoveredDevice]:
        """Feed multiple packets and return discovered devices."""
        for pkt in packets:
            self._safe_process_packet(pkt)
        return self.discovered_devices

    def _process_packet(self, packet) -> None:
        """Process captured DHCPv6 packet using scapy's native layers."""
        try:
            from scapy.all import IPv6, UDP, Ether

            src_ip = packet[IPv6].src
            sport = packet[UDP].sport

            # Extract MAC from Ethernet layer only
            src_mac = ""
            if Ether in packet:
                src_mac = packet[Ether].src.lower()
                if src_mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
                    src_mac = ""

            # Parse using scapy's native DHCPv6 layers only
            dhcp_info = self._parse_scapy_dhcpv6(packet)

            if not dhcp_info:
                return

            # Determine if this is a server or client
            is_server = sport == DHCPV6_SERVER_PORT or dhcp_info.get("msg_type_name") in (
                "Advertise",
                "Reply",
                "Reconfigure",
            )

            with self._lock:
                device_key = f"mac:{src_mac}" if src_mac else f"ip:{src_ip}"

                if device_key not in self.discovered_devices:
                    device = DiscoveredDevice(
                        mac_address=src_mac,
                        ip_addresses=[src_ip],
                        name=dhcp_info.get("fqdn", ""),
                        manufacturer="",
                        model="",
                        device_type="DHCPv6 Server" if is_server else "",
                        discovered_by=["dhcpv6"],
                        first_seen=datetime.now().isoformat(),
                        last_seen=datetime.now().isoformat(),
                    )

                    device.dhcpv6_data = {
                        "msg_type": dhcp_info.get("msg_type_name"),
                        "transaction_id": dhcp_info.get("transaction_id"),
                        "duid": dhcp_info.get("duid"),
                        "duid_type": dhcp_info.get("duid_type"),
                        "server_duid": dhcp_info.get("server_duid"),
                        "fqdn": dhcp_info.get("fqdn"),
                        "is_server": is_server,
                        "protocol": "DHCPv6/UDP",
                        "port": sport,
                    }

                    self.discovered_devices[device_key] = device

                    msg_type = dhcp_info.get("msg_type_name", "?")
                    role = "server" if is_server else "client"
                    logger.debug(f"DHCPv6: {src_ip} ({role}) {msg_type}")
                else:
                    self.discovered_devices[device_key].last_seen = datetime.now().isoformat()

        except Exception as e:
            logger.debug(f"DHCPv6 parse error: {e}")

    def _parse_scapy_dhcpv6(self, packet) -> Optional[Dict]:
        """Parse DHCPv6 using scapy's native layers."""
        if not _scapy_dhcp6.is_available:
            return None
        try:
            dhcp6 = _scapy_dhcp6()
            DHCP6_Solicit = dhcp6.DHCP6_Solicit
            DHCP6_Advertise = dhcp6.DHCP6_Advertise
            DHCP6_Request = dhcp6.DHCP6_Request
            DHCP6_Reply = dhcp6.DHCP6_Reply
            DHCP6_Confirm = dhcp6.DHCP6_Confirm
            DHCP6_Renew = dhcp6.DHCP6_Renew
            DHCP6_Rebind = dhcp6.DHCP6_Rebind
            DHCP6_Release = dhcp6.DHCP6_Release
            DHCP6_Decline = dhcp6.DHCP6_Decline
            DHCP6_Reconf = dhcp6.DHCP6_Reconf
            DHCP6_InfoRequest = dhcp6.DHCP6_InfoRequest
            DHCP6OptClientId = dhcp6.DHCP6OptClientId
            DHCP6OptServerId = dhcp6.DHCP6OptServerId
            DHCP6OptClientFQDN = dhcp6.DHCP6OptClientFQDN

            result = {}

            # Determine message type from layer
            msg_types = [
                (DHCP6_Solicit, "Solicit"),
                (DHCP6_Advertise, "Advertise"),
                (DHCP6_Request, "Request"),
                (DHCP6_Reply, "Reply"),
                (DHCP6_Confirm, "Confirm"),
                (DHCP6_Renew, "Renew"),
                (DHCP6_Rebind, "Rebind"),
                (DHCP6_Release, "Release"),
                (DHCP6_Decline, "Decline"),
                (DHCP6_Reconf, "Reconfigure"),
                (DHCP6_InfoRequest, "Information-Request"),
            ]

            found_type = None
            for layer_cls, type_name in msg_types:
                if layer_cls in packet:
                    found_type = type_name
                    dhcp_layer = packet[layer_cls]
                    if hasattr(dhcp_layer, "trid"):
                        result["transaction_id"] = dhcp_layer.trid
                    break

            if not found_type:
                return None

            result["msg_type_name"] = found_type

            # Extract Client ID (DUID)
            if DHCP6OptClientId in packet:
                client_id = packet[DHCP6OptClientId]
                if hasattr(client_id, "duid"):
                    duid_bytes = bytes(client_id.duid)
                    result["duid"] = duid_bytes.hex()
                    if len(duid_bytes) >= 2:
                        duid_type = struct.unpack(">H", duid_bytes[:2])[0]
                        result["duid_type"] = DUID_TYPES.get(duid_type, f"Unknown({duid_type})")

            # Extract Server ID
            if DHCP6OptServerId in packet:
                server_id = packet[DHCP6OptServerId]
                if hasattr(server_id, "duid"):
                    result["server_duid"] = bytes(server_id.duid).hex()

            # Extract FQDN
            if DHCP6OptClientFQDN in packet:
                fqdn_opt = packet[DHCP6OptClientFQDN]
                if hasattr(fqdn_opt, "fqdn"):
                    result["fqdn"] = str(fqdn_opt.fqdn)

            return result

        except Exception as e:
            logger.debug(f"DHCPv6 scapy parse error: {e}")
            return None


class DHCPv6ServerScanner:
    """Active DHCPv6 server discovery.

    Sends DHCPv6 Solicit to ff02::1:2 to find all DHCPv6 servers.
    """

    def __init__(self, interface: str, timeout: float = 5.0):
        self.interface = validate_interface(interface)
        self.timeout = validate_timeout(timeout)
        self.discovered_devices: Dict[str, DiscoveredDevice] = {}
        self._lock = threading.Lock()

    def scan(self) -> Dict[str, DiscoveredDevice]:
        """Send DHCPv6 Solicit and collect Advertise responses."""
        if not _scapy_all.is_available:
            logger.debug("DHCPv6 server scan: scapy not available")
            return {}
        scapy = _scapy_all()
        AsyncSniffer, IPv6, UDP = scapy.AsyncSniffer, scapy.IPv6, scapy.UDP
        Ether, conf, get_if_hwaddr = scapy.Ether, scapy.conf, scapy.get_if_hwaddr

        conf.verb = 0
        logger.debug(f"DHCPv6: Scanning for servers on {self.interface} (timeout: {self.timeout}s)")

        responses = []

        def handle_response(packet):
            try:
                if IPv6 in packet and UDP in packet:
                    if packet[UDP].sport == DHCPV6_SERVER_PORT:
                        responses.append(packet)
            except Exception as e:
                logger.debug(f"DHCPv6 response error: {e}")

        # Start listener
        sniffer = AsyncSniffer(
            iface=self.interface,
            filter=f"udp src port {DHCPV6_SERVER_PORT}",
            prn=handle_response,
            store=False,
        )
        sniffer.start()

        # Build and send DHCPv6 Solicit using Scapy layers
        try:
            solicit_layer = self._build_solicit()
            src_mac = get_if_hwaddr(self.interface)

            # IPv6 multicast MAC for ff02::1:2: 33:33:00:01:00:02
            pkt = (
                Ether(src=src_mac, dst="33:33:00:01:00:02")
                / IPv6(dst=DHCPV6_MULTICAST_ADDR, hlim=64)
                / UDP(sport=DHCPV6_CLIENT_PORT, dport=DHCPV6_SERVER_PORT)
                / solicit_layer
            )

            scapy_sendp(pkt, iface=self.interface, verbose=False)
            logger.debug("DHCPv6: Sent Solicit to ff02::1:2")

        except Exception as e:
            logger.debug(f"DHCPv6 Solicit send error: {e}")

        # Wait for responses
        time.sleep(self.timeout)
        sniffer.stop()

        # Process responses
        for pkt in responses:
            try:
                src_ip = pkt[IPv6].src

                # Extract MAC from Ethernet layer if available
                src_mac = ""
                if Ether in pkt:
                    src_mac = pkt[Ether].src

                # Use MAC as key if available, otherwise fall back to IP
                device_key = src_mac if src_mac else f"ip:{src_ip}"

                with self._lock:
                    if device_key not in self.discovered_devices:
                        device = DiscoveredDevice(
                            mac_address=src_mac,
                            ip_addresses=[src_ip],
                            device_type="DHCPv6 Server",
                            discovered_by=["dhcpv6-scan"],
                            first_seen=datetime.now().isoformat(),
                            last_seen=datetime.now().isoformat(),
                        )
                        device.dhcpv6_data = {
                            "is_server": True,
                            "protocol": "DHCPv6/UDP",
                            "port": DHCPV6_SERVER_PORT,
                        }
                        self.discovered_devices[device_key] = device
                        logger.debug(f"DHCPv6 server: {src_ip}")

            except Exception as e:
                logger.debug(f"DHCPv6 response parse error: {e}")

        logger.debug(f"DHCPv6: {len(self.discovered_devices)} servers found")
        return self.discovered_devices

    def _build_solicit(self):
        """Build DHCPv6 Solicit message using Scapy layers.

        Returns a Scapy packet layer containing:
        - DHCP6_Solicit with random transaction ID
        - Client ID option with DUID-LLT (link-layer + time)
        - Elapsed Time option (0)
        - Option Request for DNS servers
        """
        import os
        import time
        from scapy.layers.dhcp6 import (
            DHCP6_Solicit,
            DHCP6OptClientId,
            DHCP6OptElapsedTime,
            DHCP6OptOptReq,
            DUID_LLT,
        )

        # Random transaction ID (3 bytes)
        trid = int.from_bytes(os.urandom(3), "big")

        # DUID-LLT: Link-layer address + time
        base_time = 946684800  # 2000-01-01 00:00:00 UTC
        time_since = int(time.time() - base_time)
        # Random MAC for DUID (as colon-separated hex string)
        random_mac = ":".join(f"{b:02x}" for b in os.urandom(6))

        duid = DUID_LLT(type=1, hwtype=1, timeval=time_since, lladdr=random_mac)

        return (
            DHCP6_Solicit(trid=trid)
            / DHCP6OptClientId(duid=duid)
            / DHCP6OptElapsedTime(elapsedtime=0)
            / DHCP6OptOptReq(reqopts=[DHCPV6_OPT_DNS_SERVERS])
        )
