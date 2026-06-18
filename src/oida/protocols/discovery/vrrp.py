"""
VRRP (Virtual Router Redundancy Protocol) passive listener.

VRRP uses:
- IP protocol 112
- Multicast 224.0.0.18 (VRRPv2/v3 IPv4)
- Multicast ff02::12 (VRRPv3 IPv6)

Useful for discovering:
- Virtual router configurations
- Active/backup router roles
- Virtual IP addresses
- Priority configurations
"""

import threading
import time
from datetime import datetime
from typing import Dict, Iterator

from .core import (
    DiscoveredDevice,
    validate_interface,
    validate_timeout,
)
from ...utils.ics_logger import get_module_logger
from ...utils.lazy_import import lazy_import

_scapy_all = lazy_import("scapy.all", "discovery")

logger = get_module_logger(__name__)


class VRRPPassiveListener:
    """Passive VRRP traffic listener.

    Captures VRRP advertisements to identify:
    - Virtual routers (master and backup)
    - Virtual IP addresses
    - Router priorities and preemption settings

    Supports:
    - Live capture via AsyncSniffer
    - Direct packet feeding for testing
    """

    PROTOCOL_NAME = "vrrp-passive"
    BPF_FILTER = "ip proto 112"

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
        """Capture VRRP from live interface."""
        if not _scapy_all.is_available:
            logger.debug("VRRP: scapy not available")
            return {}
        scapy = _scapy_all()
        AsyncSniffer, conf = scapy.AsyncSniffer, scapy.conf

        conf.verb = 0
        logger.debug(f"VRRP: Listening on {self.interface} for {self.timeout}s")

        sniffer = AsyncSniffer(
            iface=self.interface,
            filter=self.BPF_FILTER,
            prn=self._safe_process_packet,
            store=False,
        )

        sniffer.start()
        time.sleep(self.timeout)
        sniffer.stop()

        logger.debug(f"VRRP: {len(self.discovered_devices)} routers")
        return self.discovered_devices

    def _safe_process_packet(self, packet) -> None:
        """Wrapper with error handling."""
        try:
            from scapy.layers.vrrp import VRRP

            if VRRP in packet:
                self._process_scapy_vrrp(packet)
        except Exception as e:
            logger.debug(f"VRRP packet error: {e}")

    def feed_packet(self, packet) -> None:
        """Feed a single packet for testing."""
        self._safe_process_packet(packet)

    def feed_packets(self, packets: Iterator) -> Dict[str, DiscoveredDevice]:
        """Feed multiple packets and return discovered devices."""
        for pkt in packets:
            self._safe_process_packet(pkt)
        return self.discovered_devices

    def _process_scapy_vrrp(self, packet) -> None:
        """Process VRRP packet using scapy's native VRRP layer."""
        try:
            from scapy.all import IP, Ether
            from scapy.layers.vrrp import VRRP

            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            vrrp = packet[VRRP]

            # Extract MAC from Ethernet layer if available
            src_mac = ""
            if Ether in packet:
                src_mac = packet[Ether].src

            version = vrrp.version
            vrid = vrrp.vrid
            priority = vrrp.priority
            # Only the Master sends VRRP Advertisements (RFC 5798 §6.4.3 +
            # RFC 3768 §6.4.3 for v2); Backup routers MUST NOT transmit
            # them. So observing ANY Advertisement = sender is Master,
            # regardless of priority. Previous heuristic 'priority == 255'
            # confused "IP address owner" (255) with "Master role" and
            # misclassified every default-config master (Cisco/Keepalived
            # default priority = 100) as Backup.
            vrrp_type = getattr(vrrp, "type", 1)
            is_address_owner = priority == 255

            # Extract virtual IPs
            virtual_ips = []
            if hasattr(vrrp, "addrlist") and vrrp.addrlist:
                virtual_ips = list(vrrp.addrlist)

            is_master = vrrp_type == 1

            with self._lock:
                # Use MAC as key if available, otherwise fall back to IP-based key
                device_key = src_mac if src_mac else f"vrrp:{src_ip}:{vrid}"

                if device_key not in self.discovered_devices:
                    device = DiscoveredDevice(
                        mac_address=src_mac,
                        ip_addresses=[src_ip],
                        name=f"VRRP Router (VRID {vrid})",
                        manufacturer="",
                        model="",
                        device_type="Router (VRRP Master)" if is_master else "Router (VRRP Backup)",
                        discovered_by=["vrrp-passive"],
                        first_seen=datetime.now().isoformat(),
                        last_seen=datetime.now().isoformat(),
                    )

                    # Get advertisement interval
                    adver_int = getattr(vrrp, "adv", 1) if hasattr(vrrp, "adv") else 1

                    device.vrrp_data = {
                        "version": version,
                        "vrid": vrid,
                        "priority": priority,
                        "state": 2 if is_master else 1,
                        "state_name": "Master" if is_master else "Backup",
                        "is_master": is_master,
                        "is_address_owner": is_address_owner,
                        "virtual_ips": virtual_ips,
                        "adver_int": adver_int,
                        "protocol": "VRRP",
                        "multicast_dst": dst_ip,
                    }

                    self.discovered_devices[device_key] = device

                    role = "Master" if is_master else "Backup"
                    logger.debug(f"VRRP: {src_ip} VRID={vrid} {role} pri={priority}")
                else:
                    self.discovered_devices[device_key].last_seen = datetime.now().isoformat()

        except Exception as e:
            logger.debug(f"VRRP scapy parse error: {e}")
