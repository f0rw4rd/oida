"""OSPF (Open Shortest Path First) shared constants.

Used by both pcap/passive/ospf.py (PyShark) and protocols/discovery/ospf_passive.py (Scapy).
"""

# OSPF constants
OSPF_PROTOCOL = 89
OSPF_MULTICAST_ALL_ROUTERS = "224.0.0.5"
OSPF_MULTICAST_DR = "224.0.0.6"

# OSPF packet types
OSPF_TYPES = {
    1: "Hello",
    2: "Database Description",
    3: "Link State Request",
    4: "Link State Update",
    5: "Link State Acknowledgment",
}

# OSPF authentication types
OSPF_AUTH_TYPES = {
    0: "None",
    1: "Simple Password",
    2: "Cryptographic (MD5)",
}

# OSPF network types
OSPF_NETWORK_TYPES = {
    1: "Point-to-Point",
    2: "Broadcast",
    3: "NBMA",
    4: "Point-to-Multipoint",
    5: "Virtual Link",
}
