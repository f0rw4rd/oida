"""IGMP (Internet Group Management Protocol) shared constants.

Used by both pcap/igmp.py (PyShark) and protocols/discovery/igmp.py (Scapy).
"""

# IGMP constants
IGMP_PROTOCOL = 2  # IP protocol number for IGMP

# IGMP message types
IGMP_MEMBERSHIP_QUERY = 0x11  # v1/v2/v3
IGMP_V1_MEMBERSHIP_REPORT = 0x12
IGMP_V2_MEMBERSHIP_REPORT = 0x16
IGMP_V2_LEAVE_GROUP = 0x17
IGMP_V3_MEMBERSHIP_REPORT = 0x22

# Common multicast groups and their purposes
MULTICAST_GROUPS = {
    "224.0.0.1": "All Hosts",
    "224.0.0.2": "All Routers",
    "224.0.0.5": "OSPF Routers",
    "224.0.0.6": "OSPF DRs",
    "224.0.0.9": "RIPv2",
    "224.0.0.10": "EIGRP",
    "224.0.0.13": "PIM",
    "224.0.0.18": "VRRP",
    "224.0.0.22": "IGMPv3",
    "224.0.0.102": "HSRPv2",
    "224.0.0.120": "BACnet/IP",
    "224.0.0.251": "mDNS",
    "224.0.0.252": "LLMNR",
    "224.0.1.1": "NTP",
    "224.0.1.129": "Multicast VLAN Registration",
    "239.255.255.250": "SSDP/UPnP",
    "239.255.255.253": "SSDP Search",
    "239.192.0.0/14": "Organization-Local Scope",  # Range
}

# ICS-specific multicast groups
ICS_MULTICAST_GROUPS = {
    "224.0.0.120": "BACnet/IP",
    "224.0.23.0": "PROFINET DCP",
    "224.0.23.1": "PROFINET DCP",
    "239.255.255.250": "SSDP (industrial devices)",
}
