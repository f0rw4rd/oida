"""GLBP (Gateway Load Balancing Protocol) shared constants.

Used by pcap/glbp.py (PyShark).
"""

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
