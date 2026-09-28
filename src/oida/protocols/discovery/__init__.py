"""
Unified Network Discovery Protocol

Combines multiple discovery protocols for comprehensive network scanning:

Passive Mode (--passive, default):
- LLDP: Listen for Link Layer Discovery Protocol frames
- mDNS: Browse for advertised services (Bonjour/Avahi)
- SSDP: Listen for UPnP announcements
- DCP: Listen for PROFINET device broadcasts
- CDP: Listen for Cisco Discovery Protocol frames
- STP: Listen for Spanning Tree Protocol BPDUs
- ARP: Passive ARP traffic monitoring
- IPv6: Passive IPv6 traffic monitoring (RA, NA, NS, DAD)

Active Mode (--active):
- ARP: Scan subnet for live hosts
- DCP: Send PROFINET identify requests
- SSDP: Send M-SEARCH discovery requests
- DNS-SD: Active service enumeration
- WS-Discovery: ONVIF cameras, printers, Windows devices
- LLMNR: Windows local name resolution
- KNX: Building automation discovery
- BACnet: Building automation discovery
- EtherNet/IP: Industrial protocol discovery
- CODESYS: PLC discovery
- ADS/TwinCAT: Beckhoff PLC discovery
- NetBIOS: Windows name service discovery
- Moxa: Serial device server discovery
- Lantronix: Serial device server discovery
- IPv6: Multicast ping (ff02::1, ff02::2)
- DHCP: Passive client monitoring and active server discovery
- FINS/Omron: UDP broadcast discovery for Omron PLCs

Usage:
    oida discovery eth0                    # Passive only (default)
    oida discovery eth0 --active           # Passive + Active
    oida discovery eth0 --active --no-passive  # Active only
"""

import warnings

# scapy's import chain (scapy.layers.tls) emits cryptography's FFDH
# CryptographyDeprecationWarning on every fresh interpreter with
# cryptography >= 48. Dependency noise the user cannot act on; same
# pattern as knx/__init__.py suppressing xknx warnings. Process-global
# on purpose: scanner modules import scapy.all directly inside
# functions, bypassing lazy_import's scoped filter.
warnings.filterwarnings("ignore", message=".*deprecated and support will be removed.*")

# Lazy import mapping: attribute name -> (module, name)
# This defers all heavy imports until actually accessed
_LAZY_IMPORTS = {
    # Core utilities (loaded eagerly as they're lightweight)
    # -- see below for eager imports --
    # ARP scanners
    "ARPScanner": (".arp", "ARPScanner"),
    "ARPPassiveListener": (".arp", "ARPPassiveListener"),
    "EthernetPassiveListener": (".arp", "EthernetPassiveListener"),
    # DHCP scanners
    "DHCPPassiveListener": (".dhcp", "DHCPPassiveListener"),
    "DHCPServerScanner": (".dhcp", "DHCPServerScanner"),
    # FINS/Omron scanners
    "FINSPassiveListener": (".fins", "FINSPassiveListener"),
    "FINSScanner": (".fins", "FINSScanner"),
    # HSRP router discovery
    "HSRPPassiveListener": (".hsrp", "HSRPPassiveListener"),
    # IGMP multicast discovery
    "IGMPPassiveListener": (".igmp", "IGMPPassiveListener"),
    # DHCPv6 discovery
    "DHCPv6PassiveListener": (".dhcpv6", "DHCPv6PassiveListener"),
    "DHCPv6ServerScanner": (".dhcpv6", "DHCPv6ServerScanner"),
    # ICS protocol scanners
    "ADSScanner": (".ics", "ADSScanner"),
    "BACnetScanner": (".ics", "BACnetScanner"),
    "CODESYSScanner": (".ics", "CODESYSScanner"),
    "EtherNetIPScanner": (".ics", "EtherNetIPScanner"),
    "KNXScanner": (".ics", "KNXScanner"),
    # IPv6 scanners
    "IPv6PassiveListener": (".ipv6", "IPv6PassiveListener"),
    "IPv6Scanner": (".ipv6", "IPv6Scanner"),
    # mDNS/DNS-SD scanners
    "DNSSDScanner": (".mdns", "DNSSDScanner"),
    "MDNSScanner": (".mdns", "MDNSScanner"),
    # Network protocol scanners
    "CDPPassiveListener": (".network", "CDPPassiveListener"),
    "LLMNRScanner": (".network", "LLMNRScanner"),
    "NetBIOSPassiveListener": (".network", "NetBIOSPassiveListener"),
    "NetBIOSScanner": (".network", "NetBIOSScanner"),
    "STPPassiveListener": (".network", "STPPassiveListener"),
    # Main scanner and NXC-style connection
    "DiscoveryScanner": (".scanner", "DiscoveryScanner"),
    "discovery": (".scanner", "discovery"),
    # SSDP/WS-Discovery scanners
    "SSDPScanner": (".ssdp", "SSDPScanner"),
    "WSDiscoveryScanner": (".ssdp", "WSDiscoveryScanner"),
    # Vendor-specific scanners
    "LantronixScanner": (".vendor", "LantronixScanner"),
    "MoxaScanner": (".vendor", "MoxaScanner"),
    # IT infrastructure scanners
    "HIDScanner": (".infra", "HIDScanner"),
    "MSSQLBrowserScanner": (".infra", "MSSQLBrowserScanner"),
    "BJNPScanner": (".infra", "BJNPScanner"),
    "SonicWallScanner": (".infra", "SonicWallScanner"),
    "DB2Scanner": (".infra", "DB2Scanner"),
    "SybaseScanner": (".infra", "SybaseScanner"),
    "XDMCPScanner": (".infra", "XDMCPScanner"),
    "JenkinsScanner": (".infra", "JenkinsScanner"),
    "PCAnywhereScanner": (".infra", "PCAnywhereScanner"),
    # NetManage (Schneider Electric) discovery
    "NetManageScanner": (".netmanage", "NetManageScanner"),
    "NetManagePassiveListener": (".netmanage", "NetManagePassiveListener"),
    "NetManageDevice": (".netmanage", "NetManageDevice"),
    "NetManageHeader": (".netmanage", "NetManageHeader"),
    "decode_netmanage_packet": (".netmanage", "decode_netmanage_packet"),
    "discover_netmanage": (".netmanage", "discover_netmanage"),
    # Passive traffic statistics (Wireshark-style)
    "PassiveStatistics": (".stats", "PassiveStatistics"),
}

# Core utilities - loaded eagerly as they're lightweight and commonly used
from oida.protocols.discovery.core import (
    DiscoveredDevice,
    InterfaceCapabilities,
    check_interface_capabilities,
    classify_device_type,
    compute_network_cidr,
    get_interface_ipv6,
    get_interface_network,
    lookup_mac_vendor,
    mac_to_eui64,
    normalize_ipv6,
    IPV6_ALL_NODES,
    IPV6_ALL_ROUTERS,
    MDNS_SERVICE_TYPES,
    SSDP_DEVICE_TYPES,
    SSDP_MULTICAST_ADDR,
    SSDP_MX,
    SSDP_PORT,
    WSD_DEVICE_TYPES,
)


def __getattr__(name: str):
    """Lazy import handler for deferred module loading.

    This is called when an attribute is not found in the module.
    It checks the _LAZY_IMPORTS mapping and imports on demand.
    """
    if name in _LAZY_IMPORTS:
        module_path, attr_name = _LAZY_IMPORTS[name]
        import importlib

        module = importlib.import_module(module_path, __name__)
        value = getattr(module, attr_name)
        # Cache in module globals for future access
        globals()[name] = value
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__():
    """List all available attributes including lazy imports."""
    return list(globals().keys()) + list(_LAZY_IMPORTS.keys())


__all__ = [
    # Core
    "DiscoveredDevice",
    "InterfaceCapabilities",
    "check_interface_capabilities",
    "compute_network_cidr",
    "lookup_mac_vendor",
    "get_interface_network",
    "get_interface_ipv6",
    "mac_to_eui64",
    "normalize_ipv6",
    "classify_device_type",
    # Constants
    "MDNS_SERVICE_TYPES",
    "SSDP_MULTICAST_ADDR",
    "SSDP_PORT",
    "SSDP_MX",
    "SSDP_DEVICE_TYPES",
    "WSD_DEVICE_TYPES",
    "IPV6_ALL_NODES",
    "IPV6_ALL_ROUTERS",
    # ARP
    "ARPScanner",
    "ARPPassiveListener",
    "EthernetPassiveListener",
    # DHCP
    "DHCPPassiveListener",
    "DHCPServerScanner",
    # FINS/Omron
    "FINSScanner",
    "FINSPassiveListener",
    # HSRP (v1 and v2)
    "HSRPPassiveListener",
    # IGMP
    "IGMPPassiveListener",
    # DHCPv6
    "DHCPv6PassiveListener",
    "DHCPv6ServerScanner",
    # mDNS/DNS-SD
    "MDNSScanner",
    "DNSSDScanner",
    # SSDP/WS-Discovery
    "SSDPScanner",
    "WSDiscoveryScanner",
    # Network protocols
    "LLMNRScanner",
    "CDPPassiveListener",
    "NetBIOSScanner",
    "NetBIOSPassiveListener",
    "STPPassiveListener",
    # ICS protocols
    "KNXScanner",
    "BACnetScanner",
    "EtherNetIPScanner",
    "CODESYSScanner",
    "ADSScanner",
    # Vendor-specific
    "MoxaScanner",
    "LantronixScanner",
    # IT infrastructure
    "HIDScanner",
    "MSSQLBrowserScanner",
    "BJNPScanner",
    "SonicWallScanner",
    "DB2Scanner",
    "SybaseScanner",
    "XDMCPScanner",
    "JenkinsScanner",
    "PCAnywhereScanner",
    # IPv6
    "IPv6Scanner",
    "IPv6PassiveListener",
    # Main scanner
    "DiscoveryScanner",
    "discovery",
    # NetManage (Schneider Electric)
    "NetManageScanner",
    "NetManagePassiveListener",
    "NetManageDevice",
    "NetManageHeader",
    "decode_netmanage_packet",
    "discover_netmanage",
]
