"""PIM (Protocol Independent Multicast) shared constants.

Used by both pcap/pim.py (PyShark) and protocols/discovery/pim_passive.py (Scapy).
"""

# PIM constants
PIM_PROTOCOL = 103
PIM_MULTICAST = "224.0.0.13"

# PIM message types
PIM_TYPES = {
    0: "Hello",
    1: "Register",
    2: "Register-Stop",
    3: "Join/Prune",
    4: "Bootstrap",
    5: "Assert",
    6: "Graft (PIM-DM)",
    7: "Graft-Ack (PIM-DM)",
    8: "Candidate-RP-Advertisement",
}

# PIM Hello option types
PIM_HELLO_OPTIONS = {
    1: "Hold Time",
    2: "LAN Prune Delay",
    18: "Deprecated",
    19: "DR Priority",
    20: "Generation ID",
    21: "State Refresh Capable",
    22: "Bidir Capable",
    24: "Address List",
    65001: "Cisco VxLAN",
}
