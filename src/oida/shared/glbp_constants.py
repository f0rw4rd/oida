"""GLBP (Gateway Load Balancing Protocol) shared constants.

Used by both pcap/passive/glbp.py (PyShark) and protocols/discovery/glbp.py (Scapy).
"""

# GLBP constants
GLBP_PORT = 3222
GLBP_V4_MULTICAST = "224.0.0.102"
GLBP_V6_MULTICAST = "ff02::66"

# GLBP TLV types
GLBP_TLV_HELLO = 1  # Virtual Gateway state/VIP advertisement
GLBP_TLV_REQUEST_RESPONSE = 2  # Forwarder state/virtual MAC
GLBP_TLV_AUTH = 3  # Authentication

GLBP_TLV_NAMES = {
    1: "Hello",
    2: "Request/Response",
    3: "Auth",
}

# Virtual Gateway (VG) states
GLBP_VG_STATES = {
    0x00: "Disabled",
    0x01: "Initial",
    0x02: "Learn",
    0x04: "Listen",
    0x08: "Speak",
    0x10: "Standby",
    0x20: "Active",
}

# Virtual Forwarder (VF) states
GLBP_VF_STATES = {
    0x00: "Disabled",
    0x01: "Initial",
    0x02: "Learn",
    0x04: "Listen",
    0x20: "Active",
}

# Authentication types
GLBP_AUTH_TYPES = {
    0: "None",
    1: "Plain text",
    2: "MD5 string",
    3: "MD5 chain",
}
