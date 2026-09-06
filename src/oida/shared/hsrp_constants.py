"""HSRP (Hot Standby Router Protocol) shared constants.

Used by both pcap/hsrp.py (PyShark) and protocols/discovery/hsrp.py (Scapy).
"""

# HSRP constants
HSRP_PORT = 1985
HSRP_V1_MULTICAST = "224.0.0.2"  # All routers multicast
HSRP_V2_MULTICAST = "224.0.0.102"  # HSRPv2 multicast

# HSRP opcodes (same for v1 and v2)
HSRP_OPCODES = {
    0: "Hello",
    1: "Coup",
    2: "Resign",
    3: "Advertise",  # v1 only
}

# HSRPv1 states (bitmap-based)
HSRP_V1_STATES = {
    0: "Initial",
    1: "Learn",
    2: "Listen",
    4: "Speak",
    8: "Standby",
    16: "Active",
}

# HSRPv2 states (sequential)
HSRP_V2_STATES = {
    0: "Disabled",
    1: "Init",
    2: "Learn",
    3: "Listen",
    4: "Speak",
    5: "Standby",
    6: "Active",
}

# HSRPv2 TLV types
HSRP_V2_TLV_GROUP_STATE = 1  # Group state (40 bytes)
HSRP_V2_TLV_INTERFACE_STATE = 2  # Interface state (4 bytes)
HSRP_V2_TLV_TEXT_AUTH = 3  # Text authentication (8 bytes)
HSRP_V2_TLV_MD5_AUTH = 4  # MD5 authentication (28 bytes)

HSRP_V2_TLV_NAMES = {
    1: "Group State",
    2: "Interface State",
    3: "Text Authentication",
    4: "MD5 Authentication",
}
