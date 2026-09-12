"""
Main discovery scanner and NXC-style connection class.

Contains:
- DiscoveryScanner: Unified network discovery scanner with active/passive modes
- discovery: NXC-style callable class for CLI integration
"""

import dataclasses
import ipaddress
import os
import re
import signal
import subprocess
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Any, Dict, Optional

from ...connection import SerialConnection
from ...utils.base_scanner import SerialScanner
from ...utils.export_utils import export_data
from ...utils.permissions import check_raw_socket_capability
from ...utils.protocol_helpers import SecurityAnalyzer
from ...utils.rate_limiter import scapy_srp, set_rate_limit, get_rate_limiter
from ...utils.ics_logger import get_module_logger
from ...utils.lazy_import import lazy_import

_scapy = lazy_import("scapy", "discovery")
_profinet = lazy_import("profinet", "PROFINET")
from ...utils import iface_info as _netifaces

from .arp import ARPScanner, ARPPassiveListener, EthernetPassiveListener
from .dhcp import DHCPPassiveListener, DHCPServerScanner
from .fins import FINSScanner, FINSPassiveListener
from .hsrp import HSRPPassiveListener
from .igmp import IGMPPassiveListener
from .dhcpv6 import DHCPv6PassiveListener, DHCPv6ServerScanner
from .core import (
    DiscoveredDevice,
    OutOfScopeWarning,
    build_device_description,
    check_ip_in_network_scope,
    get_interface_network,
    get_interface_networks,
    lookup_mac_vendor,
    mac_to_eui64,
    eui64_to_mac,
)
from .ics import ADSScanner, BACnetScanner, CODESYSScanner, EtherNetIPScanner, KNXScanner
from .igmp import IGMPQueryScanner
from .enrich import (
    PingEnrichScanner,
    ReverseDNSEnrichScanner,
    NetBIOSEnrichScanner,
    MDNSEnrichScanner,
)
from .ipv4_resolve import IPv4ResolveScanner
from .ipv6 import IPv6PassiveListener, IPv6Scanner
from .lldp import LLDPPassiveListener, LLDPScanner
from .mdns import DNSSDScanner, MDNSScanner, MDNSPassiveListener
from .netmanage import NetManageScanner, NetManagePassiveListener
from .network import (
    CDPPassiveListener,
    LLMNRScanner,
    NetBIOSScanner,
    NetBIOSPassiveListener,
    STPPassiveListener,
)
from .ntp import NTPPassiveListener
from .ssdp import SSDPScanner, SSDPPassiveListener, WSDiscoveryScanner
from .vendor import LantronixScanner, MoxaScanner, ADDPScanner
from .cameras import HikvisionSADPScanner, DahuaDHDiscoverScanner
from .energy import SMASpeedwireScanner
from .av import CrestronCIPScanner, ArtNetScanner
from .netgear import UbiquitiScanner, MNDPScanner
from .infra import (
    HIDScanner,
    MSSQLBrowserScanner,
    BJNPScanner,
    SonicWallScanner,
    DB2Scanner,
    SybaseScanner,
    XDMCPScanner,
    JenkinsScanner,
    PCAnywhereScanner,
    IPMIScanner,
    SLPScanner,
)
from .vrrp import VRRPPassiveListener

# Routing protocol passive listeners
from .ospf_passive import OSPFPassiveListener
from .eigrp_passive import EIGRPPassiveListener
from .rip_passive import RIPPassiveListener
from .pim_passive import PIMPassiveListener

# Scapy-based file carving listener
from .file_carving import FileCarvingListener

logger = get_module_logger(__name__)

# Scanner registry for factory pattern - reduces code duplication
# Each entry: (ScannerClass, args_builder, timeout_limit, category)
# args_builder is a lambda that takes (self) and returns constructor args tuple
# category: "passive" (listeners), "broadcast" (active probes), "ics" (ICS-specific)
_SCANNER_CONFIGS = {
    # Passive listeners - don't send packets, just listen
    "arp-passive": (
        ARPPassiveListener,
        lambda s: (s.interface, s.timeout, s.logger),
        None,
        "passive",
    ),
    "ethernet-passive": (
        EthernetPassiveListener,
        lambda s: (s.interface, s.timeout, s.logger),
        None,
        "passive",
    ),
    "ssdp-listen": (SSDPScanner, lambda s: (s.interface, s.timeout, False), None, "passive"),
    "dcp-listen": (
        SSDPScanner,
        lambda s: (s.interface, s.timeout, False),
        None,
        "passive",
    ),  # Placeholder
    "cdp": (CDPPassiveListener, lambda s: (s.interface, s.timeout), 60, "passive"),
    "stp": (STPPassiveListener, lambda s: (s.interface, s.timeout), 30, "passive"),
    "ipv6-passive": (IPv6PassiveListener, lambda s: (s.interface, s.timeout), None, "passive"),
    "dhcp-passive": (DHCPPassiveListener, lambda s: (s.interface, s.timeout), None, "passive"),
    "fins-passive": (FINSPassiveListener, lambda s: (s.interface, s.timeout), None, "passive"),
    "hsrp-passive": (HSRPPassiveListener, lambda s: (s.interface, s.timeout), None, "passive"),
    "igmp-passive": (IGMPPassiveListener, lambda s: (s.interface, s.timeout), None, "passive"),
    "dhcpv6-passive": (DHCPv6PassiveListener, lambda s: (s.interface, s.timeout), None, "passive"),
    # Scapy-based file carving
    "file-carving": (
        FileCarvingListener,
        lambda s: (s.interface, s.timeout, s.logger),
        None,
        "passive",
    ),
    # Additional Scapy-based passive listeners
    "lldp-passive": (LLDPPassiveListener, lambda s: (s.interface, s.timeout), None, "passive"),
    "mdns-passive": (MDNSPassiveListener, lambda s: (s.interface, s.timeout), None, "passive"),
    "netbios-passive": (
        NetBIOSPassiveListener,
        lambda s: (s.interface, s.timeout),
        None,
        "passive",
    ),
    "netmanage-passive": (
        NetManagePassiveListener,
        lambda s: (s.interface, s.timeout, s.logger),
        None,
        "passive",
    ),
    "ntp-passive": (NTPPassiveListener, lambda s: (s.interface, s.timeout), None, "passive"),
    "vrrp-passive": (VRRPPassiveListener, lambda s: (s.interface, s.timeout), None, "passive"),
    # Routing protocol passive listeners
    "ospf-passive": (OSPFPassiveListener, lambda s: (s.interface, s.timeout), None, "passive"),
    "eigrp-passive": (EIGRPPassiveListener, lambda s: (s.interface, s.timeout), None, "passive"),
    "rip-passive": (RIPPassiveListener, lambda s: (s.interface, s.timeout), None, "passive"),
    "pim-passive": (PIMPassiveListener, lambda s: (s.interface, s.timeout), None, "passive"),
    "ssdp-passive": (SSDPPassiveListener, lambda s: (s.interface, s.timeout), None, "passive"),
    # Broadcast/active probes - send discovery packets
    "arp": (ARPScanner, lambda s: (s.interface, s.subnet, s.arp_timeout), None, "broadcast"),
    "mdns": (MDNSScanner, lambda s: (s.interface, s.timeout, s.logger), None, "broadcast"),
    "ssdp-search": (
        SSDPScanner,
        lambda s: (s.interface, s.timeout, True, s.logger),
        10,
        "broadcast",
    ),
    "dns-sd": (DNSSDScanner, lambda s: (s.interface, s.timeout, s.logger), 15, "broadcast"),
    "ws-discovery": (WSDiscoveryScanner, lambda s: (s.interface, s.timeout), 15, "broadcast"),
    "llmnr": (LLMNRScanner, lambda s: (s.interface, s.subnet, s.timeout), 10, "broadcast"),
    "netbios": (NetBIOSScanner, lambda s: (s.interface, s.subnet, s.timeout), 10, "broadcast"),
    "dhcp-servers": (DHCPServerScanner, lambda s: (s.interface, 5.0, s.logger), 10, "broadcast"),
    "dhcpv6-servers": (DHCPv6ServerScanner, lambda s: (s.interface, 5.0), 10, "broadcast"),
    # Additional active scanners
    "lldp": (
        LLDPScanner,
        lambda s: ({"interface": s.interface, "timeout": s.timeout},),
        10,
        "broadcast",
    ),
    "igmp-query": (IGMPQueryScanner, lambda s: (s.interface, s.timeout), 10, "broadcast"),
    "netmanage": (NetManageScanner, lambda s: (s.interface, s.timeout), 10, "broadcast"),
    # ICS-specific protocols
    "knx": (KNXScanner, lambda s: (s.interface, s.timeout), 10, "ics"),
    "bacnet": (BACnetScanner, lambda s: (s.interface, s.subnet, s.timeout), 10, "ics"),
    "ethernetip": (EtherNetIPScanner, lambda s: (s.interface, s.subnet, s.timeout), 10, "ics"),
    "codesys": (CODESYSScanner, lambda s: (s.interface, s.subnet, s.timeout), 10, "ics"),
    "ads": (ADSScanner, lambda s: (s.interface, s.subnet, s.timeout), 10, "ics"),
    "moxa": (MoxaScanner, lambda s: (s.interface, s.subnet, s.timeout), 10, "ics"),
    "lantronix": (LantronixScanner, lambda s: (s.interface, s.subnet, s.timeout), 10, "ics"),
    "ipv6-ping": (IPv6Scanner, lambda s: (s.interface, s.timeout), 10, "ics"),
    "fins": (FINSScanner, lambda s: (s.interface, s.subnet, s.timeout), 10, "ics"),
    # Camera / surveillance multicast probes
    "sadp": (HikvisionSADPScanner, lambda s: (s.interface, s.timeout), 10, "broadcast"),
    "dahua": (DahuaDHDiscoverScanner, lambda s: (s.interface, s.timeout), 10, "broadcast"),
    # Energy / solar multicast probes
    "sma": (SMASpeedwireScanner, lambda s: (s.interface, s.timeout), 10, "broadcast"),
    # AV / lighting-control broadcast probes
    "crestron": (
        CrestronCIPScanner,
        lambda s: (s.interface, s.subnet, s.timeout),
        10,
        "broadcast",
    ),
    "artnet": (ArtNetScanner, lambda s: (s.interface, s.subnet, s.timeout), 10, "broadcast"),
    # BMC / network-equipment broadcast probes
    "ipmi": (IPMIScanner, lambda s: (s.interface, s.subnet, s.timeout), 10, "broadcast"),
    "ubiquiti": (UbiquitiScanner, lambda s: (s.interface, s.subnet, s.timeout), 10, "broadcast"),
    "mndp": (MNDPScanner, lambda s: (s.interface, s.subnet, s.timeout), 10, "broadcast"),
    "addp": (ADDPScanner, lambda s: (s.interface, s.subnet, s.timeout), 10, "broadcast"),
    "slp": (SLPScanner, lambda s: (s.interface, s.subnet, s.timeout), 10, "broadcast"),
    # IT infrastructure broadcast probes
    "hid": (HIDScanner, lambda s: (s.interface, s.subnet, s.timeout), 10, "broadcast"),
    "mssql": (MSSQLBrowserScanner, lambda s: (s.interface, s.subnet, s.timeout), 10, "broadcast"),
    "bjnp": (BJNPScanner, lambda s: (s.interface, s.subnet, s.timeout), 10, "broadcast"),
    "sonicwall": (SonicWallScanner, lambda s: (s.interface, s.subnet, s.timeout), 10, "broadcast"),
    "db2": (DB2Scanner, lambda s: (s.interface, s.subnet, s.timeout), 10, "broadcast"),
    "sybase": (SybaseScanner, lambda s: (s.interface, s.subnet, s.timeout), 10, "broadcast"),
    "xdmcp": (XDMCPScanner, lambda s: (s.interface, s.subnet, s.timeout), 10, "broadcast"),
    "jenkins": (JenkinsScanner, lambda s: (s.interface, s.subnet, s.timeout), 10, "broadcast"),
    "pcanywhere": (
        PCAnywhereScanner,
        lambda s: (s.interface, s.subnet, s.timeout),
        10,
        "broadcast",
    ),
}


class DiscoveryScanner(SerialScanner):
    """Unified network discovery scanner with active/passive modes"""

    def __init__(self, args: Dict[str, Any]):
        # Interface can come from "interface" or "target" arg
        if "interface" not in args or args.get("interface") is None:
            if "target" in args and args["target"]:
                args["interface"] = args["target"]
            else:
                raise ValueError("Interface is required for discovery")
        super().__init__(args)

        self.timeout = int(args.get("timeout", 3))

        # Simplified scan modes
        self.passive_mode = not args.get("no-passive", False)
        self.active_mode = args.get("active", False)
        self.arp_only_mode = args.get("arp", False)

        # ARP-only mode: disable everything except ARP
        if self.arp_only_mode:
            self.passive_mode = False
            self.active_mode = True  # ARP is an active scan

        # All protocols enabled by default when mode is enabled (unless --no-X flag passed)
        # Passive protocols (truly listen-only, no packets sent)
        self.enable_lldp = (
            self.passive_mode and not self.arp_only_mode and not args.get("no-lldp", False)
        )
        self.enable_dcp = (
            self.passive_mode and not self.arp_only_mode and not args.get("no-dcp", False)
        )
        self.enable_ssdp = (
            self.passive_mode and not self.arp_only_mode and not args.get("no-ssdp", False)
        )
        self.enable_cdp = (
            self.passive_mode and not self.arp_only_mode and not args.get("no-cdp", False)
        )
        self.enable_stp = (
            self.passive_mode and not self.arp_only_mode and not args.get("no-stp", False)
        )
        self.enable_arp_passive = self.passive_mode and not self.arp_only_mode
        self.enable_ipv6_passive = (
            self.passive_mode and not self.arp_only_mode and not args.get("no-ipv6", False)
        )
        self.enable_ethernet_passive = self.passive_mode and not self.arp_only_mode
        self.enable_dhcp_passive = (
            self.passive_mode and not self.arp_only_mode and not args.get("no-dhcp", False)
        )
        self.enable_fins_passive = (
            self.passive_mode and not self.arp_only_mode and not args.get("no-fins", False)
        )
        self.enable_hsrp_passive = (
            self.passive_mode and not self.arp_only_mode and not args.get("no-hsrp", False)
        )
        self.enable_igmp_passive = (
            self.passive_mode and not self.arp_only_mode and not args.get("no-igmp", False)
        )
        self.enable_dhcpv6_passive = (
            self.passive_mode and not self.arp_only_mode and not args.get("no-dhcp", False)
        )
        # Routing protocol passive listeners
        self.enable_ospf_passive = (
            self.passive_mode and not self.arp_only_mode and not args.get("no-ospf", False)
        )
        self.enable_eigrp_passive = (
            self.passive_mode and not self.arp_only_mode and not args.get("no-eigrp", False)
        )
        self.enable_rip_passive = (
            self.passive_mode and not self.arp_only_mode and not args.get("no-rip", False)
        )
        self.enable_pim_passive = (
            self.passive_mode and not self.arp_only_mode and not args.get("no-pim", False)
        )

        # Active protocols (send packets)
        no_arp = args.get("no-arp", False) or args.get("no_arp", False)
        self.enable_arp = (self.active_mode or self.arp_only_mode) and not no_arp
        self.enable_mdns = (
            self.active_mode and not self.arp_only_mode and not args.get("no-mdns", False)
        )
        self.enable_dnssd = (
            self.active_mode and not self.arp_only_mode and not args.get("no-dns-sd", False)
        )
        self.enable_wsdiscovery = (
            self.active_mode and not self.arp_only_mode and not args.get("no-ws-discovery", False)
        )
        self.enable_llmnr = (
            self.active_mode and not self.arp_only_mode and not args.get("no-llmnr", False)
        )
        self.enable_knx = (
            self.active_mode and not self.arp_only_mode and not args.get("no-knx", False)
        )
        self.enable_bacnet = (
            self.active_mode and not self.arp_only_mode and not args.get("no-bacnet", False)
        )
        self.enable_ethernetip = (
            self.active_mode and not self.arp_only_mode and not args.get("no-ethernetip", False)
        )
        self.enable_codesys = (
            self.active_mode and not self.arp_only_mode and not args.get("no-codesys", False)
        )
        self.enable_ads = (
            self.active_mode and not self.arp_only_mode and not args.get("no-ads", False)
        )
        self.enable_netbios = (
            self.active_mode and not self.arp_only_mode and not args.get("no-netbios", False)
        )
        self.enable_moxa = (
            self.active_mode and not self.arp_only_mode and not args.get("no-moxa", False)
        )
        self.enable_lantronix = (
            self.active_mode and not self.arp_only_mode and not args.get("no-lantronix", False)
        )
        self.enable_ipv6 = (
            self.active_mode and not self.arp_only_mode and not args.get("no-ipv6", False)
        )
        self.enable_eui64 = not self.arp_only_mode  # Skip EUI-64 in ARP-only mode
        self.enable_dhcp_servers = (
            self.active_mode and not self.arp_only_mode and not args.get("no-dhcp", False)
        )
        self.enable_fins = (
            self.active_mode and not self.arp_only_mode and not args.get("no-fins", False)
        )
        self.enable_sadp = (
            self.active_mode and not self.arp_only_mode and not args.get("no-sadp", False)
        )
        self.enable_dahua = (
            self.active_mode and not self.arp_only_mode and not args.get("no-dahua", False)
        )
        self.enable_sma = (
            self.active_mode and not self.arp_only_mode and not args.get("no-sma", False)
        )
        self.enable_crestron = (
            self.active_mode and not self.arp_only_mode and not args.get("no-crestron", False)
        )
        self.enable_artnet = (
            self.active_mode and not self.arp_only_mode and not args.get("no-artnet", False)
        )
        self.enable_ipmi = (
            self.active_mode and not self.arp_only_mode and not args.get("no-ipmi", False)
        )
        self.enable_ubiquiti = (
            self.active_mode and not self.arp_only_mode and not args.get("no-ubiquiti", False)
        )
        self.enable_mndp = (
            self.active_mode and not self.arp_only_mode and not args.get("no-mndp", False)
        )
        self.enable_addp = (
            self.active_mode and not self.arp_only_mode and not args.get("no-addp", False)
        )
        self.enable_slp = (
            self.active_mode and not self.arp_only_mode and not args.get("no-slp", False)
        )
        self.enable_dhcpv6_servers = (
            self.active_mode and not self.arp_only_mode and not args.get("no-dhcp", False)
        )

        # IT infrastructure broadcast probes
        self.enable_hid = (
            self.active_mode and not self.arp_only_mode and not args.get("no-hid", False)
        )
        self.enable_mssql = (
            self.active_mode and not self.arp_only_mode and not args.get("no-mssql", False)
        )
        self.enable_bjnp = (
            self.active_mode and not self.arp_only_mode and not args.get("no-bjnp", False)
        )
        self.enable_sonicwall = (
            self.active_mode and not self.arp_only_mode and not args.get("no-sonicwall", False)
        )
        self.enable_db2 = (
            self.active_mode and not self.arp_only_mode and not args.get("no-db2", False)
        )
        self.enable_sybase = (
            self.active_mode and not self.arp_only_mode and not args.get("no-sybase", False)
        )
        self.enable_xdmcp = (
            self.active_mode and not self.arp_only_mode and not args.get("no-xdmcp", False)
        )
        self.enable_jenkins = (
            self.active_mode and not self.arp_only_mode and not args.get("no-jenkins", False)
        )
        self.enable_pcanywhere = (
            self.active_mode and not self.arp_only_mode and not args.get("no-pcanywhere", False)
        )

        # Enrichment phase (runs after discovery to add more info)
        self.enable_enrich = self.active_mode and args.get("enrich", False)
        self.enable_ping_enrich = self.enable_enrich and not args.get("no_ping", False)
        self.enable_rdns_enrich = self.enable_enrich and not args.get("no_rdns", False)
        self.enable_netbios_enrich = self.enable_enrich and not args.get("no_netbios_enrich", False)
        self.enable_mdns_enrich = self.enable_enrich and not args.get("no_mdns_enrich", False)

        if self.enable_enrich:
            logger.debug(
                f"Enrichment enabled: ping={self.enable_ping_enrich} rdns={self.enable_rdns_enrich} netbios={self.enable_netbios_enrich} mdns={self.enable_mdns_enrich}"
            )

        # Active mode options
        self.subnet = args.get("subnet")
        self.arp_timeout = 2.0
        self.force_large_scan = args.get("force", False)

        # Output options
        self.filter_industrial = args.get("ics-only", False)
        self.resolve_mac = True

        # Continuous mode
        self.continuous_mode = args.get("continuous", False)
        self.scan_interval = int(args.get("scan-interval", 300))  # OT-safe default
        self._stop_event = threading.Event()
        self._scan_count = 0

        # Rate limiting for active scans (OT safety)
        self.rate_limit_pps = float(args.get("rate_limit", 0))
        if self.rate_limit_pps > 0:
            set_rate_limit(self.rate_limit_pps)
            interval_ms = 1000.0 / self.rate_limit_pps
            logger.info(
                f"Rate limiting enabled: {self.rate_limit_pps:.1f} pps "
                f"({interval_ms:.1f}ms between packets)"
            )
        elif self.active_mode:
            logger.debug("Rate limiting disabled (unlimited packet rate)")

        # Packet capture
        self.pcap_enabled = args.get("pcap", False)
        self.pcap_max_size_mb = args.get("pcap-max-size", 500)
        self.pcap_filter = args.get("pcap-filter", "")
        self._pcap_capture = None
        self._pcap_file = None

        self.discovered_devices: Dict[str, DiscoveredDevice] = {}
        self._ip_to_mac: Dict[str, str] = {}
        self._lock = threading.Lock()

        # Get local interface info to filter from results
        self.local_mac = self._get_local_mac()
        self.interface_caps = self._get_interface_capabilities()

        # Unreachable IP detection
        # Use user-specified network or auto-detect all networks from interface
        expected_network = args.get("expected_network")
        if expected_network:
            # User specified single network
            self.interface_networks = [expected_network]
            logger.debug(f"Using user-specified network: {expected_network}")
        else:
            # Auto-detect all networks on interface
            # This may fail for interfaces without IPv4 networks (e.g., loopback)
            # which is acceptable - scope checking will be disabled
            try:
                all_networks = get_interface_networks(self.interface)
                self.interface_networks = [cidr for _, cidr in all_networks]
                if self.interface_networks:
                    logger.debug(f"Auto-detected networks: {', '.join(self.interface_networks)}")
            except (ImportError, ValueError, RuntimeError) as e:
                logger.debug(f"Could not detect interface networks: {e}")
                self.interface_networks = []
        self.out_of_scope_warnings: list = []  # List of OutOfScopeWarning
        self.warn_out_of_scope = not args.get("no_scope_warnings", False)

    def get_protocol_name(self) -> str:
        return "discovery"

    def get_default_port(self) -> Optional[int]:
        return None

    def check_dependencies(self) -> bool:
        return _scapy.is_available

    def _get_local_mac(self) -> Optional[str]:
        """Get MAC address of the local interface to filter from results.

        Returns:
            MAC address string, or None for interfaces without MAC
            (like loopback or virtual interfaces)

        Raises:
            ImportError: Should not occur (psutil always available)
            ValueError: If interface does not exist
            RuntimeError: If unable to query interface
        """
        # Validate interface exists first
        if self.interface not in _netifaces.interfaces():
            raise ValueError(f"Interface '{self.interface}' not found")

        try:
            addrs = _netifaces.ifaddresses(self.interface)
            if _netifaces.AF_LINK in addrs:
                for addr_info in addrs[_netifaces.AF_LINK]:
                    mac = addr_info.get("addr", "")
                    if mac and mac != "00:00:00:00:00:00":
                        return mac.lower()
            # Interface exists but has no valid MAC (e.g., loopback, virtual)
            # This is valid - no MAC to filter from results
            return None
        except ValueError:
            raise  # Re-raise ValueError as-is
        except Exception as e:
            raise RuntimeError(f"Failed to get MAC for interface '{self.interface}': {e}") from e

    def _get_interface_capabilities(self):
        """Get interface capabilities for local address exclusion.

        Returns empty InterfaceCapabilities on error.
        Errors during capability detection should not prevent the scanner from running.
        """
        from .core import check_interface_capabilities, InterfaceCapabilities

        try:
            return check_interface_capabilities(self.interface)
        except (ImportError, ValueError, RuntimeError) as e:
            logger.debug(f"Could not get interface capabilities: {e}")
            return InterfaceCapabilities(interface=self.interface)

    def _check_ip_scope(self, device: DiscoveredDevice, source: str) -> None:
        """Check if device IPs are reachable from current interface and warn if not.

        Detects devices that require routing to reach - they're not on the same
        subnet as any of the interface's configured networks. This can indicate:
        misconfigured devices, VLAN leakage, multi-homed systems, or network issues.

        Args:
            device: Device to check
            source: Discovery protocol that found this device
        """
        if not self.warn_out_of_scope or not self.interface_networks:
            return

        for ip in device.ip_addresses:
            # Check if reachable from ANY of the configured networks
            reachable = False
            last_reason = ""
            for network in self.interface_networks:
                in_scope, reason = check_ip_in_network_scope(ip, interface_network=network)
                if in_scope:
                    reachable = True
                    break
                last_reason = reason

            if not reachable and ip not in device.out_of_scope_ips:
                # Track on device
                device.out_of_scope_ips.append(ip)
                device.scope_warnings.append(last_reason)

                # Create warning object with all configured networks
                networks_str = ", ".join(self.interface_networks)
                warning = OutOfScopeWarning(
                    ip=ip,
                    expected_network=networks_str,
                    device_mac=device.mac_address,
                    device_name=device.name,
                    discovered_by=source,
                    reason=last_reason,
                )
                self.out_of_scope_warnings.append(warning)

                # Log warning immediately (compact format)
                parts = [f"UNREACHABLE: {ip}"]
                if device.mac_address:
                    parts.append(f"({device.mac_address})")
                if device.name:
                    parts.append(f"[{device.name}]")
                parts.append(f"via {source}")
                self.logger.warning(" ".join(parts))

    def _format_excluded_locals(self) -> str:
        """Format local addresses for display, including network CIDR for all IPs."""
        parts = []
        if self.local_mac:
            parts.append(self.local_mac)

        # Get all network ranges for this interface
        try:
            networks = get_interface_networks(self.interface)
        except (ImportError, ValueError, RuntimeError) as e:
            self.logger.debug("format excluded locals failed: %s", e)
            networks = []
        if networks:
            for ip, cidr in networks:
                # Extract prefix length from network CIDR (e.g., /24 from 10.0.0.0/24)
                prefix = cidr.split("/")[1] if "/" in cidr else "?"
                parts.append(f"{ip}/{prefix}")
        elif self.interface_caps and self.interface_caps.ipv4_address:
            # Fallback if networks couldn't be determined
            parts.append(self.interface_caps.ipv4_address)

        # Add IPv6 addresses
        if self.interface_caps:
            for ip6 in self.interface_caps.ipv6_addresses:
                # Shorten IPv6 for display
                if len(ip6) > 25:
                    parts.append(ip6[:22] + "...")
                else:
                    parts.append(ip6)
        return ", ".join(parts) if parts else "none"

    def _start_pcap_capture(self, output_dir: str) -> bool:
        """Start background packet capture to pcap file.

        Args:
            output_dir: Directory to write pcap file

        Returns:
            True if capture started successfully

        Note:
            If interface goes down during capture, packets will be lost until
            recovery. The capture will write whatever was collected.
        """
        if not self.pcap_enabled:
            return False

        try:
            from scapy.all import AsyncSniffer, conf
            from .core import is_interface_up
            import os

            # Check interface is up before starting
            if not is_interface_up(self.interface):
                self.logger.warning(f"Interface {self.interface} is down, skipping pcap")
                return False

            conf.verb = 0

            # Create pcap file path
            self._pcap_file = os.path.join(output_dir, "capture.pcap")
            self._pcap_packets = []
            self._pcap_size = 0
            self._pcap_max_bytes = self.pcap_max_size_mb * 1024 * 1024
            self._pcap_stopped = False
            self._pcap_last_packet_time = time.time()

            def packet_handler(pkt):
                """Store packet and check size limit."""
                if self._pcap_stopped:
                    return

                self._pcap_last_packet_time = time.time()

                # Estimate packet size (rough approximation)
                pkt_size = len(bytes(pkt)) if pkt else 0
                self._pcap_size += pkt_size

                if self._pcap_size >= self._pcap_max_bytes:
                    if not self._pcap_stopped:
                        self._pcap_stopped = True
                        logger.warning(f"Pcap size limit reached ({self.pcap_max_size_mb}MB)")
                    return

                self._pcap_packets.append(pkt)

            # Build filter
            bpf_filter = self.pcap_filter if self.pcap_filter else None

            self._pcap_capture = AsyncSniffer(
                iface=self.interface,
                filter=bpf_filter,
                prn=packet_handler,
                store=False,
            )

            self._pcap_capture.start()
            self.logger.info(f"Pcap capture started (max {self.pcap_max_size_mb}MB)")
            return True

        except Exception as e:
            logger.warning(f"Could not start pcap capture: {e}")
            self._pcap_capture = None
            return False

    def _stop_pcap_capture(self) -> Optional[str]:
        """Stop packet capture and write to file.

        Returns:
            Path to pcap file if successful, None otherwise
        """
        if not self._pcap_capture:
            return None

        try:
            from scapy.all import wrpcap
            from .core import is_interface_up

            # Check if interface is currently down
            if not is_interface_up(self.interface):
                self.logger.warning(f"Interface {self.interface} is down - pcap may be incomplete")

            # Check if we stopped receiving packets (interface may have gone down)
            if hasattr(self, "_pcap_last_packet_time"):
                silence_duration = time.time() - self._pcap_last_packet_time
                if silence_duration > 5.0 and self._pcap_packets:
                    self.logger.warning(
                        f"No packets received for {silence_duration:.0f}s - interface may have dropped"
                    )

            self._pcap_capture.stop()

            if self._pcap_packets:
                wrpcap(self._pcap_file, self._pcap_packets)
                size_mb = self._pcap_size / (1024 * 1024)
                self.logger.info(
                    f"Wrote: {self._pcap_file} ({len(self._pcap_packets)} packets, {size_mb:.1f}MB)"
                )
                return self._pcap_file
            else:
                self.logger.info("No packets captured")
                return None

        except Exception as e:
            logger.warning(f"Could not write pcap: {e}")
            return None
        finally:
            self._pcap_capture = None
            self._pcap_packets = []

    def connect(self) -> Any:
        """Validate interface - raises error if not found"""
        try:
            from scapy.all import get_if_list

            interfaces = get_if_list()
            if self.interface not in interfaces:
                # Filter out veth interfaces for cleaner output
                real_interfaces = [i for i in interfaces if not i.startswith("veth")]
                self.logger.fail(
                    f"Interface '{self.interface}' not found. "
                    f"Available: {', '.join(real_interfaces[:8])}"
                )
                return None
            return self.interface
        except Exception as e:
            self.logger.debug("connect failed: %s", e)
            self.logger.fail(f"Could not validate interface: {e}")
            return None

    def disconnect(self, connection: Any = None) -> None:
        """Cleanup"""

    def discover(self, connection: Any = None) -> Dict[str, Any]:
        """Run discovery based on active/passive modes"""
        results = {
            "devices": [],
            "protocols_used": [],
            "scan_mode": [],
            "statistics": {},
            "security_analysis": {},
        }

        # Check if interface was validated
        if connection is None:
            self.logger.fail("No valid interface - cannot proceed")
            return results

        # Check raw socket capability at the start
        has_raw, raw_error = check_raw_socket_capability()
        if not has_raw:
            if raw_error == "permission_error":
                from ...utils.permissions import raw_socket_help_lines

                self.logger.fail("Raw socket access required")
                for _line in raw_socket_help_lines():
                    self.logger.display(_line)
            else:
                self.logger.fail(raw_error)
            return results

        if not self.passive_mode and not self.active_mode:
            self.logger.warning("Neither --passive nor --active enabled, using passive")
            self.passive_mode = True

        # Create output directory in temp (needed for pcap)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self._output_dir = os.path.join(
            tempfile.gettempdir(), f"discovery_{self.interface}_{timestamp}"
        )
        try:
            os.makedirs(self._output_dir, exist_ok=True)
        except Exception as e:
            logger.debug(f"Could not create output directory: {e}")
            self._output_dir = None

        # Start pcap capture if enabled
        if self.pcap_enabled and self._output_dir:
            self._start_pcap_capture(self._output_dir)

        # Continuous mode - run until Ctrl+C
        if self.continuous_mode:
            return self._run_continuous(results)

        # Build list of scan tasks
        scan_tasks = []

        # Passive mode tasks (listen only, no packets sent)
        if self.passive_mode:
            results["scan_mode"].append("passive")
            if self.enable_lldp:
                scan_tasks.append(("lldp-passive", self._run_lldp_passive))
            if self.enable_ssdp:
                scan_tasks.append(("ssdp-listen", lambda: self._run_scanner("ssdp-listen")))
            if self.enable_cdp:
                scan_tasks.append(("cdp", lambda: self._run_scanner("cdp")))
            if self.enable_stp:
                scan_tasks.append(("stp", lambda: self._run_scanner("stp")))
            # Passive traffic monitoring
            if self.enable_arp_passive:
                scan_tasks.append(("arp-passive", lambda: self._run_scanner("arp-passive")))
            if self.enable_ipv6_passive:
                scan_tasks.append(("ipv6-passive", lambda: self._run_scanner("ipv6-passive")))
            if self.enable_ethernet_passive:
                scan_tasks.append(
                    ("ethernet-passive", lambda: self._run_scanner("ethernet-passive"))
                )
            if self.enable_dhcp_passive:
                scan_tasks.append(("dhcp-passive", lambda: self._run_scanner("dhcp-passive")))
            if self.enable_fins_passive:
                scan_tasks.append(("fins-passive", lambda: self._run_scanner("fins-passive")))
            if self.enable_hsrp_passive:
                scan_tasks.append(("hsrp-passive", lambda: self._run_scanner("hsrp-passive")))
            if self.enable_igmp_passive:
                scan_tasks.append(("igmp-passive", lambda: self._run_scanner("igmp-passive")))
            if self.enable_dhcpv6_passive:
                scan_tasks.append(("dhcpv6-passive", lambda: self._run_scanner("dhcpv6-passive")))
            # Routing protocol passive listeners
            if self.enable_ospf_passive:
                scan_tasks.append(("ospf-passive", lambda: self._run_scanner("ospf-passive")))
            if self.enable_eigrp_passive:
                scan_tasks.append(("eigrp-passive", lambda: self._run_scanner("eigrp-passive")))
            if self.enable_rip_passive:
                scan_tasks.append(("rip-passive", lambda: self._run_scanner("rip-passive")))
            if self.enable_pim_passive:
                scan_tasks.append(("pim-passive", lambda: self._run_scanner("pim-passive")))

        # Active mode tasks (send packets)
        if self.active_mode:
            results["scan_mode"].append("active")
            if self.enable_arp:
                scan_tasks.append(("arp", lambda: self._run_scanner("arp")))
            if self.enable_mdns:
                scan_tasks.append(("mdns", lambda: self._run_scanner("mdns")))
            if self.enable_dcp:
                scan_tasks.append(("dcp-identify", self._run_dcp_active))
            if self.enable_ssdp:
                scan_tasks.append(("ssdp-search", lambda: self._run_scanner("ssdp-search")))
            if self.enable_dnssd:
                scan_tasks.append(("dns-sd", lambda: self._run_scanner("dns-sd")))
            if self.enable_wsdiscovery:
                scan_tasks.append(("ws-discovery", lambda: self._run_scanner("ws-discovery")))
            if self.enable_llmnr:
                scan_tasks.append(("llmnr", lambda: self._run_scanner("llmnr")))
            if self.enable_knx:
                scan_tasks.append(("knx", lambda: self._run_scanner("knx")))
            if self.enable_bacnet:
                scan_tasks.append(("bacnet", lambda: self._run_scanner("bacnet")))
            if self.enable_ethernetip:
                scan_tasks.append(("ethernetip", lambda: self._run_scanner("ethernetip")))
            if self.enable_codesys:
                scan_tasks.append(("codesys", lambda: self._run_scanner("codesys")))
            if self.enable_ads:
                scan_tasks.append(("ads", lambda: self._run_scanner("ads")))
            if self.enable_netbios:
                scan_tasks.append(("netbios", lambda: self._run_scanner("netbios")))
            if self.enable_moxa:
                scan_tasks.append(("moxa", lambda: self._run_scanner("moxa")))
            if self.enable_lantronix:
                scan_tasks.append(("lantronix", lambda: self._run_scanner("lantronix")))
            # IPv6 active discovery
            if self.enable_ipv6:
                scan_tasks.append(("ipv6-ping", lambda: self._run_scanner("ipv6-ping")))
            # DHCP server discovery
            if self.enable_dhcp_servers:
                scan_tasks.append(("dhcp-servers", lambda: self._run_scanner("dhcp-servers")))
            # FINS/Omron PLC discovery
            if self.enable_fins:
                scan_tasks.append(("fins", lambda: self._run_scanner("fins")))
            # Hikvision SADP camera/NVR discovery
            if self.enable_sadp:
                scan_tasks.append(("sadp", lambda: self._run_scanner("sadp")))
            # Dahua DHDiscover camera/NVR discovery
            if self.enable_dahua:
                scan_tasks.append(("dahua", lambda: self._run_scanner("dahua")))
            # SMA Speedwire inverter / energy-meter discovery
            if self.enable_sma:
                scan_tasks.append(("sma", lambda: self._run_scanner("sma")))
            # Crestron CIP AV control-system discovery
            if self.enable_crestron:
                scan_tasks.append(("crestron", lambda: self._run_scanner("crestron")))
            # Art-Net lighting-node discovery
            if self.enable_artnet:
                scan_tasks.append(("artnet", lambda: self._run_scanner("artnet")))
            # IPMI / ASF-RMCP BMC discovery
            if self.enable_ipmi:
                scan_tasks.append(("ipmi", lambda: self._run_scanner("ipmi")))
            # Ubiquiti device discovery
            if self.enable_ubiquiti:
                scan_tasks.append(("ubiquiti", lambda: self._run_scanner("ubiquiti")))
            # MikroTik MNDP discovery
            if self.enable_mndp:
                scan_tasks.append(("mndp", lambda: self._run_scanner("mndp")))
            # Digi ADDP serial-device-server discovery
            if self.enable_addp:
                scan_tasks.append(("addp", lambda: self._run_scanner("addp")))
            # SLP service-agent discovery
            if self.enable_slp:
                scan_tasks.append(("slp", lambda: self._run_scanner("slp")))
            # DHCPv6 server discovery
            if self.enable_dhcpv6_servers:
                scan_tasks.append(("dhcpv6-servers", lambda: self._run_scanner("dhcpv6-servers")))

            # IT infrastructure broadcast probes
            for _infra_name in [
                "hid",
                "mssql",
                "bjnp",
                "sonicwall",
                "db2",
                "sybase",
                "xdmcp",
                "jenkins",
                "pcanywhere",
            ]:
                if getattr(self, f"enable_{_infra_name}", False):
                    scan_tasks.append((_infra_name, lambda n=_infra_name: self._run_scanner(n)))

        if not scan_tasks:
            self.logger.warning("No discovery methods enabled")
            return results

        # Group tasks by category from registry (no more hardcoded lists)
        def get_task_category(task_name: str) -> str:
            """Get category from registry, handling special cases"""
            # Handle special task names that map to registry entries
            name_map = {"dcp-identify": "dcp-listen"}
            lookup_name = name_map.get(task_name, task_name)
            config = _SCANNER_CONFIGS.get(lookup_name)
            if config and len(config) >= 4:
                return config[3]
            # Default: passive for listeners, broadcast otherwise
            # Include known passive protocols that don't have "-passive" or "-listen" in name
            passive_protos = ("passive", "listen", "lldp", "cdp", "stp")
            return "passive" if any(p in task_name for p in passive_protos) else "broadcast"

        passive_tasks = [(n, f) for n, f in scan_tasks if get_task_category(n) == "passive"]
        broadcast_tasks = [(n, f) for n, f in scan_tasks if get_task_category(n) == "broadcast"]
        ics_tasks = [(n, f) for n, f in scan_tasks if get_task_category(n) == "ics"]

        def run_tasks(tasks, timeout_per_task=None, max_workers=None):
            """Run tasks in parallel, return when all complete"""
            if not tasks:
                return {}
            task_timeout = timeout_per_task or (self.timeout + 5)
            task_results = {}
            # Default: 8 workers, but allow override for passive-only scans
            workers = max_workers or min(len(tasks), 8)

            def run_with_logging(name, func):
                """Wrapper to log task start/stop with timing"""
                logger.debug(f"[>] {name}")
                start = time.time()
                try:
                    result = func()
                    elapsed = time.time() - start
                    count = len(result) if result else 0
                    if count > 0:
                        self.logger.success(f"[<] {name}: {count} devices ({elapsed:.1f}s)")
                    else:
                        logger.debug(f"[<] {name}: done ({elapsed:.1f}s)")
                    return result
                except Exception as e:
                    elapsed = time.time() - start
                    logger.debug(f"[<] {name}: error {e} ({elapsed:.1f}s)")
                    raise

            with ThreadPoolExecutor(max_workers=workers) as executor:
                futures = {
                    executor.submit(run_with_logging, name, func): name for name, func in tasks
                }
                try:
                    for future in as_completed(futures, timeout=task_timeout):
                        task_name = futures[future]
                        try:
                            devices = future.result(timeout=task_timeout)
                            self._merge_devices(devices, task_name)
                            results["protocols_used"].append(task_name)
                            task_results[task_name] = len(devices) if devices else 0
                            # Log ARP results
                            if task_name == "arp" and devices:
                                self.logger.success(f"ARP: {len(devices)} hosts found")
                        except Exception as e:
                            logger.debug(f"{task_name}: {e}")
                except TimeoutError:
                    logger.debug(f"Tasks timed out after {task_timeout}s")
            return task_results

        # Combine active tasks (broadcast + ICS)
        active_tasks = broadcast_tasks + ics_tasks

        # Passive listeners run for at least the user-specified timeout
        # This ensures they capture responses during entire active scan
        total_scan_time = self.timeout

        if passive_tasks and active_tasks:
            # Run passive listeners concurrently with active tasks
            # Passive keeps running until executor completes (all active tasks done)
            self.logger.info(f"Scanning {self.interface} ({total_scan_time}s, passive + active)...")
            self.logger.info(f"Excluding locals: {self._format_excluded_locals()}")

            # Run all tasks together - passive listens while active probes.
            # Passive scanners already received their timeout via args_builder,
            # so no per-task wrapping is needed.
            all_tasks = passive_tasks + active_tasks
            # Executor timeout: user timeout + buffer for active tasks
            executor_timeout = total_scan_time + 60
            # Use enough workers for ALL tasks to run in parallel
            run_tasks(all_tasks, timeout_per_task=executor_timeout, max_workers=len(all_tasks))

        elif passive_tasks:
            # Passive only - run ALL tasks in parallel (they all listen for same duration)
            self.logger.info(f"Passive listening on {self.interface} ({total_scan_time}s)...")
            self.logger.info(f"Excluding locals: {self._format_excluded_locals()}")
            run_tasks(passive_tasks, max_workers=len(passive_tasks))

        elif active_tasks:
            # Active only - run all active tasks together
            self.logger.info(f"Active scanning {self.interface} ({total_scan_time}s)...")
            self.logger.info(f"Excluding locals: {self._format_excluded_locals()}")
            run_tasks(active_tasks, timeout_per_task=max(total_scan_time + 15, 30))

        # Correlate IP-only devices with MACs from ARP results
        self._correlate_ips_to_macs()

        # Check system ARP cache for MACs (from mDNS/DNS-SD responses)
        self._resolve_macs_from_arp_cache()

        # Probe remaining IP-only devices via ARP (same subnet only)
        self._resolve_macs_via_arp()

        # Resolve IPv4 for devices that only have MAC/IPv6 (passive: check cache)
        resolved = self._resolve_ipv4_for_mac_only()
        if resolved:
            self.logger.info(f"Resolved {resolved} IPv4 addresses from ARP cache")

        # Active ARP sweep to find IPv4 for remaining IPv6-only devices
        if self.active_mode:
            resolved = self._run_ipv4_resolve_scanner()
            if resolved:
                self.logger.info(f"IPv4 resolve: found {resolved} addresses for IPv6-only devices")

        # Enrichment phase: ping, reverse DNS, NetBIOS/mDNS lookups
        if self.enable_enrich:
            self._run_enrichment_phase()

        # EUI-64: Derive potential IPv6 link-local addresses from known MACs
        if self.enable_eui64:
            self._derive_eui64_addresses()
            # In active mode, ping the derived EUI-64 addresses
            if self.active_mode:
                self._ping_eui64_addresses()

        # Convert to list
        results["devices"] = [self._device_to_dict(d) for d in self.discovered_devices.values()]

        # Filter industrial if requested
        if self.filter_industrial:
            results["devices"] = [d for d in results["devices"] if self._is_industrial(d)]

        # Resolve MAC vendors if not already done
        if self.resolve_mac:
            for device in results["devices"]:
                if device.get("mac_address") and not device.get("manufacturer"):
                    vendor = lookup_mac_vendor(device["mac_address"])
                    if vendor and vendor != "Unknown":
                        device["manufacturer"] = vendor

        # Generate statistics
        results["statistics"] = self._generate_statistics()

        # Security analysis
        results["security_analysis"] = self._analyze_security(results)

        # Include out-of-scope warnings
        if self.out_of_scope_warnings:
            results["out_of_scope_warnings"] = [
                {
                    "ip": w.ip,
                    "expected_network": w.expected_network,
                    "device_mac": w.device_mac,
                    "device_name": w.device_name,
                    "discovered_by": w.discovered_by,
                    "reason": w.reason,
                }
                for w in self.out_of_scope_warnings
            ]

        # Stop pcap capture
        if self._pcap_capture:
            self._stop_pcap_capture()

        # Write output files (CSV, IPv4 list, IPv6 list)
        self._write_output_files(results)

        # Report findings
        self._report_findings(results)

        # Log rate limiting summary if enabled
        rate_limiter = get_rate_limiter()
        if rate_limiter and rate_limiter.packet_count > 0:
            logger.info(
                f"Rate limiting: sent {rate_limiter.packet_count} packets "
                f"at {rate_limiter.packets_per_second:.1f} pps"
            )

        return results

    def _run_continuous(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Run discovery continuously until Ctrl+C.

        Runs passive listeners indefinitely and active scans at intervals.
        Shows live updates when new devices are discovered or updated.
        """
        # Set up signal handler for graceful shutdown (only in main thread)
        original_handler = None
        in_main_thread = threading.current_thread() is threading.main_thread()

        if in_main_thread:
            original_handler = signal.getsignal(signal.SIGINT)

            def signal_handler(signum, frame):
                self.logger.info("\n[!] Stopping continuous discovery...")
                self._stop_event.set()

            signal.signal(signal.SIGINT, signal_handler)

        mode_str = (
            "+".join(
                [
                    m
                    for m in [
                        "passive" if self.passive_mode else "",
                        "active" if self.active_mode else "",
                    ]
                    if m
                ]
            ).upper()
            or "PASSIVE"
        )
        self.logger.success(f"Continuous discovery [{mode_str}] on {self.interface}")
        self.logger.info(f"Excluding locals: {self._format_excluded_locals()}")
        self.logger.info(f"Active scan interval: {self.scan_interval}s | Press Ctrl+C to stop")
        self.logger.info("-" * 60)

        try:
            last_active_scan = 0
            previous_device_count = 0

            while not self._stop_event.is_set():
                self._scan_count += 1
                current_time = time.time()
                scan_tasks = []

                # Always run passive listeners (registry timeout limits apply)
                if self.passive_mode:
                    if self.enable_lldp:
                        scan_tasks.append(("lldp-passive", self._run_lldp_passive))
                    if self.enable_ssdp:
                        scan_tasks.append(("ssdp-listen", lambda: self._run_scanner("ssdp-listen")))
                    if self.enable_cdp:
                        scan_tasks.append(("cdp", lambda: self._run_scanner("cdp")))
                    if self.enable_arp_passive:
                        scan_tasks.append(("arp-passive", lambda: self._run_scanner("arp-passive")))
                    if self.enable_ipv6_passive:
                        scan_tasks.append(
                            ("ipv6-passive", lambda: self._run_scanner("ipv6-passive"))
                        )

                # Run active scans at intervals
                run_active = self.active_mode and (
                    current_time - last_active_scan >= self.scan_interval
                )
                if run_active:
                    last_active_scan = current_time
                    if self.enable_arp:
                        scan_tasks.append(("arp", lambda: self._run_scanner("arp")))
                    if self.enable_mdns:
                        scan_tasks.append(("mdns", lambda: self._run_scanner("mdns")))
                    if self.enable_dcp:
                        scan_tasks.append(("dcp-identify", self._run_dcp_active))
                    if self.enable_ssdp:
                        scan_tasks.append(("ssdp-search", lambda: self._run_scanner("ssdp-search")))
                    if self.enable_dnssd:
                        scan_tasks.append(("dns-sd", lambda: self._run_scanner("dns-sd")))
                    if self.enable_wsdiscovery:
                        scan_tasks.append(
                            ("ws-discovery", lambda: self._run_scanner("ws-discovery"))
                        )
                    if self.enable_llmnr:
                        scan_tasks.append(("llmnr", lambda: self._run_scanner("llmnr")))
                    if self.enable_knx:
                        scan_tasks.append(("knx", lambda: self._run_scanner("knx")))
                    if self.enable_bacnet:
                        scan_tasks.append(("bacnet", lambda: self._run_scanner("bacnet")))
                    if self.enable_ethernetip:
                        scan_tasks.append(("ethernetip", lambda: self._run_scanner("ethernetip")))
                    if self.enable_codesys:
                        scan_tasks.append(("codesys", lambda: self._run_scanner("codesys")))
                    if self.enable_ads:
                        scan_tasks.append(("ads", lambda: self._run_scanner("ads")))
                    if self.enable_netbios:
                        scan_tasks.append(("netbios", lambda: self._run_scanner("netbios")))
                    if self.enable_moxa:
                        scan_tasks.append(("moxa", lambda: self._run_scanner("moxa")))
                    if self.enable_lantronix:
                        scan_tasks.append(("lantronix", lambda: self._run_scanner("lantronix")))
                    if self.enable_ipv6:
                        scan_tasks.append(("ipv6-ping", lambda: self._run_scanner("ipv6-ping")))

                if not scan_tasks:
                    time.sleep(1)
                    continue

                # Run tasks in parallel (if any)
                if scan_tasks:
                    with ThreadPoolExecutor(
                        max_workers=min(len(scan_tasks), 4)
                    ) as executor:  # OT-safe
                        futures = {executor.submit(func): name for name, func in scan_tasks}

                        for future in as_completed(futures):
                            if self._stop_event.is_set():
                                break
                            task_name = futures[future]
                            try:
                                devices = future.result()
                                self._merge_devices_live(devices, task_name)
                                if task_name not in results["protocols_used"]:
                                    results["protocols_used"].append(task_name)
                            except Exception as e:
                                logger.debug(f"{task_name}: {e}")

                # Show status periodically
                current_count = len(self.discovered_devices)
                if current_count != previous_device_count:
                    previous_device_count = current_count
                    self.logger.info(f"[Scan #{self._scan_count}] Total devices: {current_count}")

                # Short sleep between cycles
                if not self._stop_event.is_set():
                    time.sleep(0.5)

        finally:
            # Restore original signal handler (only if we set it)
            if in_main_thread and original_handler is not None:
                signal.signal(signal.SIGINT, original_handler)

            # Finalize results
            self._correlate_ips_to_macs()
            self._resolve_macs_from_arp_cache()
            if self.enable_eui64:
                self._derive_eui64_addresses()

            results["devices"] = [self._device_to_dict(d) for d in self.discovered_devices.values()]
            if self.filter_industrial:
                results["devices"] = [d for d in results["devices"] if self._is_industrial(d)]
            if self.resolve_mac:
                for device in results["devices"]:
                    if device.get("mac_address") and not device.get("manufacturer"):
                        vendor = lookup_mac_vendor(device["mac_address"])
                        if vendor and vendor != "Unknown":
                            device["manufacturer"] = vendor

            results["statistics"] = self._generate_statistics()
            results["security_analysis"] = self._analyze_security(results)
            results["scan_mode"] = ["continuous"]

            # Stop pcap capture
            if self._pcap_capture:
                self._stop_pcap_capture()

            # Write output files
            self._write_output_files(results)

            self.logger.info("-" * 60)
            self._report_findings(results)

        return results

    def _merge_devices_live(self, devices: Dict[str, DiscoveredDevice], source: str) -> None:
        """Merge devices with live status updates (NEW/UPD)."""
        with self._lock:
            for key, device in devices.items():
                # Skip local interface MAC
                mac = device.mac_address
                if mac and self.local_mac and mac.lower() == self.local_mac:
                    continue

                # Find existing device using correlation (same logic as _merge_devices)
                existing = None
                existing_key = None
                ip = device.ip_addresses[0] if device.ip_addresses else None

                # Priority 1: Direct key match
                if key in self.discovered_devices:
                    existing = self.discovered_devices[key]
                    existing_key = key
                # Priority 2: MAC match
                elif mac and mac in self.discovered_devices:
                    existing = self.discovered_devices[mac]
                    existing_key = mac
                # Priority 3: IP→MAC correlation
                elif ip and ip in self._ip_to_mac:
                    existing_mac = self._ip_to_mac[ip]
                    if existing_mac in self.discovered_devices:
                        existing = self.discovered_devices[existing_mac]
                        existing_key = existing_mac
                # Priority 4: IP-keyed device
                elif ip and f"ip:{ip}" in self.discovered_devices:
                    existing = self.discovered_devices[f"ip:{ip}"]
                    existing_key = f"ip:{ip}"

                if existing:
                    # Update existing device
                    old_sources = set(existing.discovered_by)
                    existing.merge_from(device)
                    new_sources = set(existing.discovered_by)

                    # If we now have MAC and were IP-keyed, re-key by MAC
                    if existing_key and existing_key.startswith("ip:") and existing.mac_address:
                        new_mac = existing.mac_address
                        self.discovered_devices[new_mac] = existing
                        del self.discovered_devices[existing_key]
                        for dev_ip in existing.ip_addresses:
                            self._ip_to_mac[dev_ip] = new_mac

                    # Check for out-of-scope IPs after merge
                    self._check_ip_scope(existing, source)

                    # Only log if we got new info
                    if new_sources != old_sources:
                        name = existing.name or existing.mac_address or existing_key
                        self.logger.display(f"  [UPD] {name} via {source}")
                else:
                    # New device - key by MAC if available, otherwise by IP
                    if mac:
                        self.discovered_devices[mac] = device
                        for dev_ip in device.ip_addresses:
                            self._ip_to_mac[dev_ip] = mac
                    elif ip:
                        self.discovered_devices[f"ip:{ip}"] = device
                    else:
                        self.discovered_devices[key] = device

                    # Check for out-of-scope IPs
                    self._check_ip_scope(device, source)

                    name = device.name or device.mac_address or key
                    ip_str = f" ({device.ip_addresses[0]})" if device.ip_addresses else ""
                    self.logger.success(f"  [NEW] {name}{ip_str} via {source}")

                # Track IP-to-MAC mappings
                if device.mac_address:
                    for ip in device.ip_addresses:
                        self._ip_to_mac[ip] = device.mac_address

    def _run_scanner(self, name: str) -> Dict[str, DiscoveredDevice]:
        """Generic scanner runner using registry pattern.

        Args:
            name: Scanner name from _SCANNER_CONFIGS registry

        Returns:
            Dict of discovered devices keyed by MAC or IP
        """
        config = _SCANNER_CONFIGS.get(name)
        if not config:
            logger.warning(f"Unknown scanner: {name}")
            return {}

        # Unpack config (4 elements: class, builder, timeout_limit, category)
        scanner_class, args_builder, timeout_limit, _category = config

        # Build args, applying timeout limit if specified
        # Skip ARP - it uses its own arp_timeout and shouldn't be limited
        args = list(args_builder(self))
        if timeout_limit is not None and name != "arp":
            # Apply timeout limit to any numeric arg that looks like a timeout
            # (safer than exact float comparison which can fail)
            for i, arg in enumerate(args):
                if isinstance(arg, (int, float)) and arg > 0 and arg <= 300:
                    # Likely a timeout arg - cap it
                    args[i] = min(arg, timeout_limit)
                    break

        # Check ARP scan targets and confirm if large network
        if name == "arp":
            subnet = self.subnet or get_interface_network(self.interface)
            if subnet:
                host_count = self._get_arp_host_count(subnet)
                if host_count > 255 and not self.force_large_scan:
                    self.logger.warning(f"ARP scan: {subnet} ({host_count} hosts)")
                    try:
                        response = input(f"Scan {host_count} hosts? [y/N] ")
                        if response.lower() != "y":
                            self.logger.info("ARP scan skipped")
                            return {}
                    except (EOFError, KeyboardInterrupt):
                        self.logger.info("ARP scan skipped")
                        return {}
                else:
                    self.logger.info(f"ARP scan: {subnet} ({host_count} hosts)")

        scanner = scanner_class(*args)
        return scanner.scan()

    def _get_arp_host_count(self, subnet: str) -> int:
        """Get number of hosts in subnet."""
        try:
            network = ipaddress.IPv4Network(subnet, strict=False)
            # Usable-host count without materializing hosts(): a wide subnet
            # (e.g. /8) would otherwise allocate ~16.7M address objects here,
            # stalling/OOMing before the >255-host confirmation gate can warn.
            # num_addresses minus the network + broadcast addresses matches
            # len(list(network.hosts())) exactly; /31 and /32 reserve neither.
            if network.prefixlen >= 31:
                return network.num_addresses
            return network.num_addresses - 2
        except ValueError as e:
            self.logger.debug("get arp host count failed: %s", e)
            return 0

    def _run_lldp_passive(self) -> Dict[str, DiscoveredDevice]:
        """Run LLDP passive listening"""
        from .lldp import LLDPScanner

        try:
            scanner = LLDPScanner(
                {
                    "interface": self.interface,
                    "target": self.interface,
                    "capture-time": self.timeout,
                    "passive-only": True,
                    "filter-industrial": False,
                    "quiet": True,  # Suppress sub-scanner progress
                }
            )

            conn = scanner.connect()
            if not conn:
                logger.debug("LLDP: could not connect to interface")
                return {}

            result = scanner.discover(conn)
            scanner.disconnect(conn)

            devices = {}
            for lldp_dev in result.get("devices", []):
                dev_dict = lldp_dev if isinstance(lldp_dev, dict) else lldp_dev.__dict__
                mac = dev_dict.get("mac_address", "")
                if mac:
                    # Parse LLDP data to extract structured info
                    parsed = self._parse_lldp_description(dev_dict)

                    # Extract capabilities
                    caps = dev_dict.get("capabilities", [])
                    device_type = ", ".join(caps) if isinstance(caps, list) else str(caps)

                    device = DiscoveredDevice(
                        mac_address=mac,
                        ip_addresses=dev_dict.get("management_addresses", []),
                        name=dev_dict.get("system_name", ""),
                        manufacturer=parsed.get("manufacturer", ""),
                        model=parsed.get("model", ""),
                        description=dev_dict.get("system_description", ""),
                        device_type=device_type,
                        discovered_by=["lldp"],
                        first_seen=dev_dict.get("first_seen", ""),
                        last_seen=dev_dict.get("last_seen", ""),
                        lldp_data={
                            **dev_dict,
                            # Add parsed structured data
                            "parsed_manufacturer": parsed.get("manufacturer", ""),
                            "parsed_model": parsed.get("model", ""),
                            "parsed_article_number": parsed.get("article_number", ""),
                            "parsed_firmware": parsed.get("firmware", ""),
                            "parsed_hardware": parsed.get("hardware", ""),
                            "parsed_serial": parsed.get("serial", ""),
                            "port_description": dev_dict.get("port_description", ""),
                        },
                    )
                    # Override manufacturer from MAC lookup if not parsed
                    if self.resolve_mac and not device.manufacturer:
                        vendor = lookup_mac_vendor(mac)
                        if vendor and vendor != "Unknown":
                            device.manufacturer = vendor
                    devices[mac] = device

            return devices

        except PermissionError as e:
            logger.warning(f"LLDP: permission denied (need root): {e}")
        except OSError as e:
            logger.warning(f"LLDP: network error: {e}")
        except ValueError as e:
            logger.debug(f"LLDP: invalid data: {e}")

        return {}

    def _parse_lldp_description(self, lldp_data: Dict[str, Any]) -> Dict[str, str]:
        """Parse LLDP system_description to extract structured device info.

        Handles formats like:
        - Siemens: "Siemens, SIMATIC S7, CPU-1200, 6ES7 214-1BG40-0XB0, HW: 1, FW: V.4.1.3, S C-E6S04921"
        - Cisco: "Cisco IOS Software, C2960 Software..."
        - Generic: "Model XYZ, Firmware 1.2.3"
        """
        result = {
            "manufacturer": "",
            "model": "",
            "article_number": "",
            "firmware": "",
            "hardware": "",
            "serial": "",
        }

        sys_desc = lldp_data.get("system_description", "")
        if not sys_desc:
            return result

        # Siemens format: "Siemens, SIMATIC S7, CPU-1200, 6ES7..., HW: 1, FW: V.x.x.x, S SERIAL"
        if "Siemens" in sys_desc or "SIMATIC" in sys_desc:
            result["manufacturer"] = "Siemens"
            parts = [p.strip() for p in sys_desc.split(",")]

            for i, part in enumerate(parts):
                # Model: CPU-1200, ET 200SP, etc.
                if "CPU-" in part or "ET " in part or "CP " in part:
                    result["model"] = part
                # Article number: 6ES7 xxx-xxxx-xxxx
                elif part.startswith("6") and len(part) > 10:
                    result["article_number"] = part
                # Firmware: FW: V.x.x.x or just V.x.x.x
                elif "FW:" in part or (part.startswith("V") and "." in part):
                    result["firmware"] = part.replace("FW:", "").strip()
                # Hardware: HW: x
                elif "HW:" in part:
                    result["hardware"] = part.replace("HW:", "").strip()
                # Serial: S XXXXX (usually last part starting with S)
                elif part.startswith("S ") and i == len(parts) - 1:
                    result["serial"] = part[2:].strip()

            # Also check SIMATIC model in parts
            for part in parts:
                if "SIMATIC" in part:
                    if not result["model"]:
                        result["model"] = part

        # Cisco format
        elif "Cisco" in sys_desc:
            result["manufacturer"] = "Cisco"
            # Extract model from "Cisco IOS Software, C2960 Software" or similar
            match = re.search(r"([A-Z]+\d+[A-Z]*)", sys_desc)
            if match:
                result["model"] = match.group(1)

        # Beckhoff format
        elif "Beckhoff" in sys_desc or "TwinCAT" in sys_desc:
            result["manufacturer"] = "Beckhoff"
            parts = sys_desc.split(",")
            for part in parts:
                part = part.strip()
                if "CX" in part or "EK" in part or "EL" in part:
                    result["model"] = part

        # Schneider format
        elif "Schneider" in sys_desc or "Modicon" in sys_desc:
            result["manufacturer"] = "Schneider Electric"
            parts = sys_desc.split(",")
            for part in parts:
                part = part.strip()
                if "M340" in part or "M580" in part or "Quantum" in part:
                    result["model"] = part

        # Phoenix Contact format
        elif "Phoenix" in sys_desc:
            result["manufacturer"] = "Phoenix Contact"

        # WAGO format
        elif "WAGO" in sys_desc:
            result["manufacturer"] = "WAGO"
            match = re.search(r"(\d{3,4}-\d{4})", sys_desc)
            if match:
                result["article_number"] = match.group(1)

        # Generic firmware extraction
        if not result["firmware"]:
            # Look for version patterns
            fw_patterns = [
                r"FW[:\s]*([Vv]?[\d.]+)",
                r"Firmware[:\s]*([Vv]?[\d.]+)",
                r"Version[:\s]*([Vv]?[\d.]+)",
                r"\bV(\d+\.\d+\.?\d*)\b",
            ]
            for pattern in fw_patterns:
                match = re.search(pattern, sys_desc)
                if match:
                    result["firmware"] = match.group(1)
                    break

        return result

    def _run_dcp_active(self) -> Dict[str, DiscoveredDevice]:
        """Run DCP active identify (PROFINET)"""
        if not _profinet.is_available:
            logger.debug("DCP: profinet-py not installed (pip install oida[discovery])")
            return {}
        profinet = _profinet()
        from profinet.dcp import read_response, DCPDeviceDescription

        try:
            # Create socket and get MAC
            sock = profinet.ethernet_socket(self.interface, 0x8892)
            my_mac = profinet.get_mac(self.interface)

            # Send discover and read responses
            profinet.send_discover(sock, my_mac)
            responses = read_response(sock, my_mac, timeout_sec=min(int(self.timeout), 10))

            sock.close()

            if not responses:
                return {}

            # Convert raw responses to DCPDeviceDescription objects
            devices = []
            for mac_bytes, blocks in responses.items():
                try:
                    dcp_desc = DCPDeviceDescription(mac_bytes, blocks)
                    devices.append(dcp_desc)
                except Exception as e:
                    logger.debug(f"DCP: failed to parse device: {e}")

            return self._convert_dcp_devices(devices, "dcp-identify")

        except PermissionError as e:
            logger.warning(f"DCP: permission denied (need root): {e}")
        except OSError as e:
            logger.warning(f"DCP: network error: {e}")
        except Exception as e:
            logger.debug(f"DCP: error: {e}")

        return {}

    def _convert_dcp_devices(self, dcp_devices: list, source: str) -> Dict[str, DiscoveredDevice]:
        """Convert profinet-py DCPDeviceDescription list to DiscoveredDevice dict"""
        from datetime import datetime

        devices = {}
        now = datetime.now().isoformat()

        for dcp_dev in dcp_devices:
            mac = getattr(dcp_dev, "mac", "")
            if not mac:
                continue

            ips = []
            ip = getattr(dcp_dev, "ip", "")
            if ip and ip != "0.0.0.0":
                ips.append(ip)

            dcp_data = {
                "mac_address": mac,
                "name_of_station": getattr(dcp_dev, "name", ""),
                "ip_address": ip,
                "subnet_mask": getattr(dcp_dev, "netmask", ""),
                "gateway": getattr(dcp_dev, "gateway", ""),
                "vendor_id": getattr(dcp_dev, "vendor_id", 0),
                "device_id": getattr(dcp_dev, "device_id", 0),
                "manufacturer_name": getattr(dcp_dev, "vendor_name", ""),
            }

            device = DiscoveredDevice(
                mac_address=mac,
                ip_addresses=ips,
                name=getattr(dcp_dev, "name", ""),
                manufacturer=getattr(dcp_dev, "vendor_name", ""),
                model="",
                device_type="PROFINET IO-Device",
                discovered_by=[source],
                first_seen=now,
                last_seen=now,
                dcp_data=dcp_data,
            )
            devices[mac] = device

        return devices

    def _derive_eui64_addresses(self) -> int:
        """Derive potential IPv6 link-local addresses from known MAC addresses.

        EUI-64 format embeds MAC address into IPv6 link-local address.
        This runs at the END of discovery to enrich devices with likely IPv6 addresses.

        NOTE: Derived addresses are stored in ipv6_data["eui64_derived"] but NOT
        added to ip_addresses until verified by ping (in active mode).

        Returns number of devices with derived EUI-64 addresses.
        """
        enriched = 0
        with self._lock:
            for key, device in self.discovered_devices.items():
                if not device.mac_address:
                    continue

                # Derive EUI-64 link-local address
                eui64_addr = mac_to_eui64(device.mac_address)
                if not eui64_addr:
                    continue

                # Check if we already have this address (from actual traffic)
                if eui64_addr in device.ip_addresses:
                    continue

                # Update or create ipv6_data - store as derived, NOT in ip_addresses
                if device.ipv6_data is None:
                    device.ipv6_data = {
                        "addresses": [],
                        "eui64_derived": [],
                    }

                if "eui64_derived" not in device.ipv6_data:
                    device.ipv6_data["eui64_derived"] = []

                # Only track as derived - don't add to ip_addresses yet
                if eui64_addr not in device.ipv6_data["eui64_derived"]:
                    device.ipv6_data["eui64_derived"].append(eui64_addr)
                    enriched += 1
                    logger.debug(f"EUI-64: {device.mac_address} -> {eui64_addr} (derived)")

        if enriched:
            logger.debug(
                f"EUI-64: Derived {enriched} potential IPv6 addresses (pending verification)"
            )
        return enriched

    def _ping_eui64_addresses(self) -> int:
        """Ping derived EUI-64 link-local addresses to verify reachability.

        Runs after _derive_eui64_addresses() in active mode.
        Updates devices with reachability status.

        Returns number of devices that responded to ping.
        """
        # Collect EUI-64 addresses to ping
        addresses_to_ping = []
        with self._lock:
            for device in self.discovered_devices.values():
                if device.ipv6_data and device.ipv6_data.get("eui64_derived"):
                    for addr in device.ipv6_data["eui64_derived"]:
                        addresses_to_ping.append((device.mac_address, addr))

        if not addresses_to_ping:
            return 0

        from ...utils.platform_compat import build_ping_command

        responded = 0
        for mac, addr in addresses_to_ping:
            try:
                # Ping6 with interface scope for link-local
                # Format: fe80::xxxx%interface
                scoped_addr = f"{addr}%{self.interface}"
                cmd = build_ping_command(scoped_addr, count=1, timeout=1, ipv6=True)
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    timeout=3,
                )
                if result.returncode == 0:
                    responded += 1
                    # Mark as verified AND add to ip_addresses
                    with self._lock:
                        for device in self.discovered_devices.values():
                            if device.mac_address == mac:
                                if "eui64_verified" not in device.ipv6_data:
                                    device.ipv6_data["eui64_verified"] = []
                                device.ipv6_data["eui64_verified"].append(addr)
                                # Now add to ip_addresses since it's verified
                                if addr not in device.ip_addresses:
                                    device.ip_addresses.append(addr)
                                if "eui64-ping" not in device.discovered_by:
                                    device.discovered_by.append("eui64-ping")
                                logger.debug(f"EUI-64 ping: {addr} verified")
                                break
                else:
                    logger.debug(f"EUI-64 ping: {addr} no response")
            except subprocess.TimeoutExpired:
                logger.debug(f"EUI-64 ping: {addr} timeout")
            except Exception as e:
                logger.debug(f"EUI-64 ping: {addr} error: {e}")

        return responded

    def _merge_devices(self, new_devices: Dict[str, DiscoveredDevice], source: str) -> None:
        """Merge newly discovered devices into main collection with status tracking."""
        with self._lock:
            for key, device in new_devices.items():
                mac = device.mac_address
                ip = device.ip_addresses[0] if device.ip_addresses else None

                # Skip local interface MAC
                if mac and self.local_mac and mac.lower() == self.local_mac:
                    logger.debug(f"Filtering local interface MAC: {mac}")
                    continue

                # Try to find existing device
                existing = None
                existing_key = None

                # Priority 1: MAC match
                if mac and mac in self.discovered_devices:
                    existing = self.discovered_devices[mac]
                    existing_key = mac
                # Priority 2: IP→MAC correlation
                elif ip and ip in self._ip_to_mac:
                    existing_mac = self._ip_to_mac[ip]
                    if existing_mac in self.discovered_devices:
                        existing = self.discovered_devices[existing_mac]
                        existing_key = existing_mac
                # Priority 3: IP-keyed device
                elif ip and f"ip:{ip}" in self.discovered_devices:
                    existing = self.discovered_devices[f"ip:{ip}"]
                    existing_key = f"ip:{ip}"

                if existing:
                    # UPDATE: Merge into existing, track what changed
                    changes = existing.merge_from(device)
                    # A previously-seen device is no longer "new"; clearing this
                    # lets _report_findings emit UPD instead of labelling every
                    # device NEW (is_new defaults True and was never reset).
                    existing.is_new = False
                    if changes:
                        existing.updated_fields = list(changes)
                        logger.debug(f"[{source}] Updated {existing_key}: +{changes}")

                    # If we now have MAC and were IP-keyed, re-key
                    if existing_key.startswith("ip:") and existing.mac_address:
                        new_mac = existing.mac_address
                        self.discovered_devices[new_mac] = existing
                        del self.discovered_devices[existing_key]
                        for dev_ip in existing.ip_addresses:
                            self._ip_to_mac[dev_ip] = new_mac

                    # Check for out-of-scope IPs after merge
                    self._check_ip_scope(existing, source)
                else:
                    # NEW: First time seeing this device
                    device.is_new = True
                    device.updated_fields = ["new_device"]

                    # Check for out-of-scope IPs
                    self._check_ip_scope(device, source)

                    if mac:
                        self.discovered_devices[mac] = device
                        for dev_ip in device.ip_addresses:
                            self._ip_to_mac[dev_ip] = mac
                        # Show new device in NXC style
                        vendor = lookup_mac_vendor(mac)
                        ip_str = f" ({ip})" if ip else ""
                        vendor_str = f" [{vendor}]" if vendor and vendor != "Unknown" else ""
                        self.logger.success(f"Found: {mac}{ip_str}{vendor_str} via {source}")
                    elif ip:
                        self.discovered_devices[f"ip:{ip}"] = device
                        self.logger.success(f"Found: {ip} via {source}")
                    else:
                        self.discovered_devices[f"unknown:{key}"] = device

    def _correlate_ips_to_macs(self) -> int:
        """Correlate IP-only devices with MAC addresses from ARP or EUI-64.

        Returns number of devices that were correlated.
        """
        correlated = 0
        with self._lock:
            # First pass: extract MAC from IPv6 EUI-64 link-local addresses
            for key, device in list(self.discovered_devices.items()):
                if device.mac_address:
                    continue  # Already has MAC
                for ip in device.ip_addresses:
                    if ip.startswith("fe80::"):
                        mac = eui64_to_mac(ip)
                        if mac:
                            device.mac_address = mac
                            if not device.manufacturer:
                                device.manufacturer = lookup_mac_vendor(mac)
                            device.updated_fields.append("mac_address")
                            logger.debug(f"EUI-64 extracted: {ip} -> {mac}")
                            # Re-key device by MAC
                            if key.startswith("ip:"):
                                if mac in self.discovered_devices:
                                    self.discovered_devices[mac].merge_from(device)
                                    del self.discovered_devices[key]
                                else:
                                    self.discovered_devices[mac] = device
                                    del self.discovered_devices[key]
                                correlated += 1
                            break

            # Build IP→MAC lookup from all MAC-keyed devices
            for key, device in self.discovered_devices.items():
                if device.mac_address and not key.startswith("ip:"):
                    for ip in device.ip_addresses:
                        self._ip_to_mac[ip] = device.mac_address

            # Re-key IP-only devices by MAC if we found one
            for key in list(self.discovered_devices.keys()):
                if not key.startswith("ip:"):
                    continue

                device = self.discovered_devices[key]
                for ip in device.ip_addresses:
                    if ip in self._ip_to_mac:
                        mac = self._ip_to_mac[ip]
                        device.mac_address = mac
                        device.updated_fields.append("mac_address")

                        # Merge into MAC-keyed device if exists
                        if mac in self.discovered_devices:
                            changes = self.discovered_devices[mac].merge_from(device)
                            del self.discovered_devices[key]
                            logger.debug(f"Correlated {ip} -> {mac}: +{changes}")
                        else:
                            # Re-key from IP to MAC
                            self.discovered_devices[mac] = device
                            del self.discovered_devices[key]
                            logger.debug(f"Re-keyed {key} -> {mac}")

                        correlated += 1
                        break

        if correlated:
            logger.info(f"Correlated {correlated} IP-only devices to MACs")
        return correlated

    def _resolve_macs_from_arp_cache(self) -> int:
        """Resolve MAC addresses from system ARP cache.

        After receiving mDNS/DNS-SD responses, the kernel should have
        ARP entries for those IPs. Reads the system ARP cache cross-platform.
        Returns number of MACs resolved.
        """
        from ...utils.platform_compat import get_arp_cache_as_ip_to_mac

        resolved = 0
        arp_cache = get_arp_cache_as_ip_to_mac()

        if not arp_cache:
            return 0

        with self._lock:
            for key in list(self.discovered_devices.keys()):
                if not key.startswith("ip:"):
                    continue

                device = self.discovered_devices[key]
                for ip in device.ip_addresses:
                    if ip in arp_cache:
                        mac = arp_cache[ip]
                        device.mac_address = mac
                        device.updated_fields.append("mac_from_cache")

                        # Look up vendor
                        vendor = lookup_mac_vendor(mac)
                        if vendor and vendor != "Unknown" and not device.manufacturer:
                            device.manufacturer = vendor

                        # Re-key from IP to MAC
                        if mac in self.discovered_devices:
                            self.discovered_devices[mac].merge_from(device)
                            del self.discovered_devices[key]
                        else:
                            self.discovered_devices[mac] = device
                            del self.discovered_devices[key]

                        self._ip_to_mac[ip] = mac
                        resolved += 1
                        logger.debug(f"ARP cache: {ip} -> {mac}")
                        break

        if resolved:
            logger.info(f"ARP cache resolved {resolved} MAC addresses")
        return resolved

    def _resolve_macs_via_arp(self) -> int:
        """Resolve MAC addresses for IP-only devices via ARP probe.

        Sends ARP requests for IPs that don't have MAC addresses.
        Returns number of MACs resolved.
        """
        resolved = 0
        ips_to_resolve = []

        with self._lock:
            for key, device in self.discovered_devices.items():
                if key.startswith("ip:") and device.ip_addresses:
                    for ip in device.ip_addresses:
                        # Only resolve IPv4 addresses
                        if not ip.startswith("127.") and ":" not in ip:
                            ips_to_resolve.append((key, ip))

        if not ips_to_resolve:
            return 0

        from scapy.all import ARP, Ether, conf

        try:
            conf.verb = 0
            logger.debug(f"ARP probing {len(ips_to_resolve)} IP-only devices")

            for key, ip in ips_to_resolve:
                try:
                    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
                    ans, _ = scapy_srp(pkt, iface=self.interface, timeout=1, verbose=0)

                    for _, recv in ans:
                        mac = recv.hwsrc.lower()
                        if mac and mac != "00:00:00:00:00:00":
                            with self._lock:
                                if key in self.discovered_devices:
                                    device = self.discovered_devices[key]
                                    device.mac_address = mac
                                    device.updated_fields.append("mac_resolved")

                                    # Look up vendor
                                    vendor = lookup_mac_vendor(mac)
                                    if vendor and vendor != "Unknown" and not device.manufacturer:
                                        device.manufacturer = vendor

                                    # Re-key from IP to MAC
                                    if mac in self.discovered_devices:
                                        self.discovered_devices[mac].merge_from(device)
                                        del self.discovered_devices[key]
                                    else:
                                        self.discovered_devices[mac] = device
                                        del self.discovered_devices[key]

                                    self._ip_to_mac[ip] = mac
                                    resolved += 1
                                    logger.debug(f"ARP probe: {ip} -> {mac}")
                            break

                except Exception as e:
                    logger.debug(f"ARP probe failed for {ip}: {e}")

        except Exception as e:
            logger.debug(f"ARP probe error: {e}")

        if resolved:
            logger.info(f"ARP probed {resolved} MAC addresses")
        return resolved

    def _resolve_ipv4_for_mac_only(self) -> int:
        """Resolve IPv4 addresses for devices that only have MAC or IPv6.

        Checks the system ARP cache (which maps IP -> MAC) and inverts it
        to find IPv4 addresses for devices that only have MAC addresses.

        Returns number of IPv4 addresses resolved.
        """
        from ...utils.platform_compat import get_arp_cache_as_mac_to_ips

        resolved = 0
        mac_to_ipv4 = get_arp_cache_as_mac_to_ips()

        if not mac_to_ipv4:
            return 0

        with self._lock:
            for mac, device in self.discovered_devices.items():
                if not device.mac_address:
                    continue

                # Check if device only has IPv6 or no IP at all
                has_ipv4 = any(":" not in ip for ip in device.ip_addresses)
                if has_ipv4:
                    continue

                # Look up IPv4 from ARP cache
                mac_lower = device.mac_address.lower()
                if mac_lower in mac_to_ipv4:
                    for ipv4 in mac_to_ipv4[mac_lower]:
                        if ipv4 not in device.ip_addresses:
                            device.ip_addresses.insert(0, ipv4)  # IPv4 first
                            device.updated_fields.append("ipv4_from_cache")
                            self._ip_to_mac[ipv4] = device.mac_address
                            resolved += 1
                            logger.debug(f"ARP cache: {device.mac_address} -> {ipv4}")

        return resolved

    def _run_ipv4_resolve_scanner(self) -> int:
        """Run IPv4 resolve scanner for devices that only have MAC/IPv6.

        Uses the dedicated IPv4ResolveScanner to do an ARP sweep and
        correlate responses by MAC address.

        Returns number of IPv4 addresses resolved.
        """
        # Find devices with MAC but no IPv4
        macs_to_resolve = {}
        with self._lock:
            for key, device in self.discovered_devices.items():
                if not device.mac_address:
                    continue
                # Check if device only has IPv6 or no IP at all
                has_ipv4 = any(":" not in ip for ip in device.ip_addresses)
                if has_ipv4:
                    continue
                macs_to_resolve[device.mac_address] = device

        if not macs_to_resolve:
            return 0

        logger.debug(f"IPv4 resolve: {len(macs_to_resolve)} devices need IPv4")

        try:
            scanner = IPv4ResolveScanner(
                interface=self.interface,
                timeout=3,
                subnet=self.subnet,
                macs_to_resolve=macs_to_resolve,
            )
            results = scanner.scan()

            # Update IP-to-MAC mappings for resolved devices
            resolved = 0
            with self._lock:
                for mac, device in results.items():
                    for ip in device.ip_addresses:
                        if ":" not in ip:  # IPv4
                            self._ip_to_mac[ip] = device.mac_address
                            resolved += 1

            return resolved

        except Exception as e:
            logger.debug(f"IPv4 resolve scanner error: {e}")
            return 0

    def _run_enrichment_phase(self) -> None:
        """Run enrichment scanners to add more info to discovered devices.

        Runs after main discovery to:
        - Ping hosts to verify they're alive
        - Reverse DNS lookups for hostnames
        - NetBIOS name resolution
        - mDNS name resolution
        """
        if not self.discovered_devices:
            return

        self.logger.info(f"Enrichment: processing {len(self.discovered_devices)} devices")

        # Ping verification
        if self.enable_ping_enrich:
            try:
                scanner = PingEnrichScanner(
                    interface=self.interface,
                    timeout=2,
                    devices=self.discovered_devices,
                )
                results = scanner.scan()
                if results:
                    self.logger.success(f"Ping: {len(results)} hosts alive")
            except Exception as e:
                logger.debug(f"Ping enrich error: {e}")

        # Reverse DNS
        if self.enable_rdns_enrich:
            try:
                scanner = ReverseDNSEnrichScanner(
                    interface=self.interface,
                    timeout=2,
                    devices=self.discovered_devices,
                )
                results = scanner.scan()
                if results:
                    self.logger.success(f"Reverse DNS: {len(results)} hostnames resolved")
            except Exception as e:
                logger.debug(f"Reverse DNS enrich error: {e}")

        # NetBIOS names
        if self.enable_netbios_enrich:
            try:
                scanner = NetBIOSEnrichScanner(
                    interface=self.interface,
                    timeout=2,
                    devices=self.discovered_devices,
                )
                results = scanner.scan()
                if results:
                    self.logger.success(f"NetBIOS: {len(results)} names resolved")
            except Exception as e:
                logger.debug(f"NetBIOS enrich error: {e}")

        # mDNS names
        if self.enable_mdns_enrich:
            try:
                scanner = MDNSEnrichScanner(
                    interface=self.interface,
                    timeout=2,
                    devices=self.discovered_devices,
                )
                results = scanner.scan()
                if results:
                    self.logger.success(f"mDNS: {len(results)} names resolved")
            except Exception as e:
                logger.debug(f"mDNS enrich error: {e}")

    def _device_to_dict(self, device: DiscoveredDevice) -> Dict[str, Any]:
        """Convert DiscoveredDevice to dictionary.

        Serializes every dataclass field so that protocol-specific payloads
        (ntp_data, rip_data, hsrp_data, the IT-infra dicts, etc.) reach the
        export path instead of being silently dropped by a hand-maintained
        allowlist that drifts behind the dataclass definition.
        """
        return {f.name: getattr(device, f.name) for f in dataclasses.fields(device)}

    def _is_industrial(self, device: Dict[str, Any]) -> bool:
        """Check if device appears to be industrial/ICS"""
        industrial_keywords = [
            "plc",
            "hmi",
            "scada",
            "siemens",
            "beckhoff",
            "schneider",
            "rockwell",
            "allen-bradley",
            "omron",
            "mitsubishi",
            "abb",
            "profinet",
            "modbus",
            "ethercat",
            "s7",
            "wago",
            "phoenix",
            "codesys",
            "moxa",
            "lantronix",
            "nport",
            "oncell",
            "mgate",
            "xport",
            "automation",
            "industrial",
            "controller",
        ]

        text_to_check = " ".join(
            [
                device.get("name", ""),
                device.get("manufacturer", ""),
                device.get("model", ""),
                device.get("description", ""),
                device.get("device_type", ""),
            ]
        ).lower()

        return any(kw in text_to_check for kw in industrial_keywords)

    def _generate_statistics(self) -> Dict[str, Any]:
        """Generate discovery statistics"""
        stats = {
            "total_devices": len(self.discovered_devices),
            "devices_with_mac": 0,
            "devices_with_ip": 0,
            "manufacturer_distribution": {},
            "protocol_distribution": {},
        }

        # Add rate limiting info
        rate_limiter = get_rate_limiter()
        if rate_limiter:
            stats["rate_limiting"] = {
                "enabled": True,
                "packets_per_second": rate_limiter.packets_per_second,
                "packets_sent": rate_limiter.packet_count,
                "interval_ms": rate_limiter.interval * 1000,
            }
        else:
            stats["rate_limiting"] = {"enabled": False}

        for device in self.discovered_devices.values():
            if device.mac_address:
                stats["devices_with_mac"] += 1
            if device.ip_addresses:
                stats["devices_with_ip"] += 1

            mfr = device.manufacturer or "Unknown"
            stats["manufacturer_distribution"][mfr] = (
                stats["manufacturer_distribution"].get(mfr, 0) + 1
            )

            for proto in device.discovered_by:
                stats["protocol_distribution"][proto] = (
                    stats["protocol_distribution"].get(proto, 0) + 1
                )

        return stats

    def _analyze_security(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze security aspects of discovery"""
        analysis = SecurityAnalyzer.assess_protocol_security(
            {
                "authentication": False,
                "authorization": False,
                "encryption": False,
                "integrity_check": False,
                "access_control": False,
            }
        )

        findings = []
        devices = results.get("devices", [])

        if devices:
            findings.append(f"Discovered {len(devices)} devices on network")

        mdns_count = sum(1 for d in devices if d.get("mdns_services"))
        ssdp_count = sum(1 for d in devices if d.get("ssdp_data"))
        arp_count = sum(1 for d in devices if d.get("arp_data"))

        if arp_count:
            findings.append(f"{arp_count} hosts responded to ARP")
        if mdns_count:
            findings.append(f"{mdns_count} devices advertising mDNS services")
        if ssdp_count:
            findings.append(f"{ssdp_count} devices responding to SSDP")

        industrial = [d for d in devices if self._is_industrial(d)]
        if industrial:
            findings.append(f"Found {len(industrial)} industrial/ICS devices")

        analysis["findings"] = findings
        return analysis

    def _report_findings(self, results: Dict[str, Any]) -> None:
        """Report discovery findings"""
        devices = results.get("devices", [])

        if not devices:
            self.logger.info("No devices discovered")
            return

        headers = ["Status", "MAC", "Vendor", "IP", "Description"]
        table_data = []

        new_count = 0
        update_count = 0

        for device in devices:
            # Determine status
            is_new = device.get("is_new", True)
            updated_fields = device.get("updated_fields", [])

            if is_new:
                status = "NEW"
                new_count += 1
            elif updated_fields:
                status = "UPD"
                update_count += 1
            else:
                status = "   "

            mac = device.get("mac_address", "") or "(unknown)"
            ips = device.get("ip_addresses", [])
            # Show all IPs (IPv4 first, then IPv6)
            # Keep 0.0.0.0 only if no other valid IPs (shows device is trying DHCP)
            ipv4s = [ip for ip in ips if ":" not in ip and ip]
            ipv6s = [ip for ip in ips if ":" in ip and ip]
            valid_ipv4s = [ip for ip in ipv4s if ip != "0.0.0.0"]
            # Show 0.0.0.0 only if no valid IPv4 and no IPv6
            if valid_ipv4s or ipv6s:
                ip = ", ".join(valid_ipv4s + ipv6s)
            elif "0.0.0.0" in ipv4s:
                ip = "0.0.0.0 (no DHCP)"
            else:
                ip = ""

            # Build rich description from all protocol data
            description = self._build_device_description(device)

            # In verbose mode, append discovery reasons to description
            if self.debug:
                reasons = device.get("discovery_reasons", [])
                if reasons:
                    description += f" ({', '.join(reasons)})"

            # Resolve MAC vendor
            vendor = device.get("manufacturer", "")
            if not vendor and mac != "(unknown)":
                vendor = lookup_mac_vendor(mac)

            table_data.append([status, mac, vendor[:15], ip, description])

        export_data(
            data=table_data,
            headers=headers,
            output_format=self.export_format,
            filename_prefix="network_discovery",
            title="Network Discovery Results",
            logger=self.logger,
        )

        stats = results.get("statistics", {})
        self.logger.info(
            f"Discovered {stats.get('total_devices', 0)} devices "
            f"({new_count} new, {update_count} updated, "
            f"{stats.get('devices_with_mac', 0)} with MAC)"
        )

    def _build_device_description(self, device: Dict[str, Any]) -> str:
        """Build a rich description from all available protocol data.

        Delegates to the shared build_device_description() in core.py.
        """
        return build_device_description(device, verbose=self.debug)

    def _write_output_files(self, results: Dict[str, Any]) -> None:
        """Write discovery results to files: CSV table, IPv4 list, IPv6 list.

        Files are written only when ``-o`` is given (mirrors the rest of the
        framework). Without ``-o`` the results stay console-only; the temp
        ``_output_dir`` is reserved for pcap capture, which needs a real path.
        """
        devices = results.get("devices", [])
        if not devices:
            return

        # Gate file output on -o, like the rest of the framework. No -o ->
        # console only, don't litter /tmp with CSV/IP lists.
        from ...utils.export_utils import get_config

        output_dir = get_config().get("output_dir")
        if not output_dir:
            return
        output_dir = str(output_dir)

        # Collect all IPs (filter out invalid ones)
        ipv4_list = []
        ipv6_list = []
        for device in devices:
            for ip in device.get("ip_addresses", []):
                if not ip or ip == "0.0.0.0":
                    continue
                if ":" in ip:
                    if not ip.startswith("::"):  # Skip invalid IPv6
                        ipv6_list.append(ip)
                else:
                    ipv4_list.append(ip)

        # Write CSV table
        try:
            headers = [
                "mac_address",
                "ip_addresses",
                "manufacturer",
                "name",
                "description",
                "discovered_by",
            ]
            rows = []
            for device in devices:
                rows.append(
                    [
                        device.get("mac_address", ""),
                        ",".join(device.get("ip_addresses", [])),
                        device.get("manufacturer", ""),
                        device.get("name", ""),
                        self._build_device_description(device),
                        ",".join(device.get("discovered_by", [])),
                    ]
                )
            export_data(
                rows,
                headers,
                output_format="csv",
                output_dir=output_dir,
                filename_prefix="devices",
                logger=self.logger,
            )
        except Exception as e:
            logger.debug(f"Could not write CSV: {e}")

        # Write IPv4 list
        if ipv4_list:
            from pathlib import Path

            ipv4_path = Path(output_dir) / "ipv4.txt"
            try:
                unique_ips = sorted(set(ipv4_list))
                ipv4_path.write_text("\n".join(unique_ips) + "\n", encoding="utf-8")
                self.logger.info(f"Wrote: {ipv4_path} ({len(unique_ips)} addresses)")
            except Exception as e:
                logger.debug(f"Could not write IPv4 list: {e}")

        # Write IPv6 list
        if ipv6_list:
            from pathlib import Path

            ipv6_path = Path(output_dir) / "ipv6.txt"
            try:
                unique_ips = sorted(set(ipv6_list))
                ipv6_path.write_text("\n".join(unique_ips) + "\n", encoding="utf-8")
                self.logger.info(f"Wrote: {ipv6_path} ({len(unique_ips)} addresses)")
            except Exception as e:
                logger.debug(f"Could not write IPv6 list: {e}")


class discovery(SerialConnection):
    """NXC-style unified network discovery (callable)"""

    def __init__(self, args, db, host):
        self.protocol_name = "DISCOVERY"
        self.default_port = None
        self._scan_results = None
        super().__init__(args, db, host)

    def proto_flow(self):
        """Main discovery workflow"""
        args_dict = self._convert_args_to_dict()
        self.scanner = DiscoveryScanner(args_dict)

        # Validate interface - exit early if not found
        if not self.create_conn_obj():
            return

        self.enum_host_info()
        self.print_host_info()
        self._execute_scan()

    def _convert_args_to_dict(self) -> Dict[str, Any]:
        """Override to handle discovery interface fallback and debug flag.

        Also preserves underscore keys that DiscoveryScanner expects
        (the base class converts all underscores to hyphens).
        """
        result = super()._convert_args_to_dict()
        # Interface fallback: --interface > target > self.interface
        result["interface"] = (
            getattr(self.args, "interface", None)
            or getattr(self.args, "target", None)
            or self.interface
        )
        # Debug from verbose
        result["debug"] = getattr(self.args, "debug", False) or getattr(self.args, "verbose", 0) > 0
        return result

    def create_conn_obj(self) -> bool:
        """Validate interface - returns False if not found"""
        self.logger.info(f"Initializing interface {self.interface}")
        self._connection = self.scanner.connect()
        if self._connection is not None:
            self.logger.success(f"Listening on interface {self.interface}")
        else:
            self.logger.fail(f"Failed to initialize interface {self.interface}")
        return self._connection is not None

    def enum_host_info(self) -> None:
        """Required NXC framework hook; discovery has no per-host enumeration step."""

    def print_host_info(self) -> None:
        """Required NXC framework hook; discovery prints findings via _report_findings."""

    def _execute_scan(self) -> None:
        """Execute discovery scan"""
        try:
            self._scan_results = self.scanner.discover(self._connection)
        except Exception as e:
            self.logger.debug("execute scan failed: %s", e)
            self.logger.fail(f"Discovery error: {e}")

    def cleanup(self) -> None:
        """Cleanup scanner"""
        if hasattr(self, "scanner"):
            self.scanner.disconnect(None)

    def get_results(self) -> Dict[str, Any]:
        """Return scan results"""
        if self._scan_results:
            return {
                "host": self.interface,
                "protocol": "discovery",
                "success": True,
                "data": self._scan_results,
            }
        return {
            "host": self.interface,
            "protocol": "discovery",
            "success": False,
        }
