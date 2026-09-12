"""PIM (Protocol Independent Multicast) shared constants.

Used by both pcap/pim.py (PyShark) and protocols/discovery/pim_passive.py (Scapy).
"""

# PIM constants
PIM_PROTOCOL = 103
PIM_MULTICAST = "224.0.0.13"

# PIM message types -- IANA "PIM Message Types" registry
# https://www.iana.org/assignments/pim-parameters/pim-parameters.txt
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
    9: "State Refresh (PIM-DM)",
    10: "DF Election (Bidir-PIM)",
    11: "ECMP Redirect",
    12: "PIM Flooding Mechanism",
    13: "PIM Packed Register",
}

# PIM Hello option types -- IANA "PIM-Hello Options" registry.
# 65001 is NOT a VxLAN option: both IANA (65001-65535 = private use) and
# Wireshark's packet-pim.c (PIM_HELLO_ADDR_LST, "Address list, old
# implementation") record it as the legacy Address List option.
PIM_HELLO_OPTIONS = {
    1: "Hold Time",
    2: "LAN Prune Delay",
    17: "Label Parameters",
    18: "Deprecated",
    19: "DR Priority",
    20: "Generation ID",
    21: "State-Refresh",
    22: "Bidirectional Capable",  # IANA: "Bidirectional Capable" (RFC 5015)
    23: "VCI Capability",
    24: "Address List",
    25: "Neighbor List TLV",
    26: "Join Attribute",
    27: "PIM-over-TCP-Capable",
    28: "PIM-over-SCTP-Capable",
    29: "Pop-Count",
    30: "PIM MT-ID",
    31: "Interface ID",
    32: "PIM ECMP Redirect Hello Option",
    33: "vPC Peer ID",
    34: "DR Load-Balancing Capability",
    35: "DR Load-Balancing List",
    36: "Hierarchical Join/Prune Attribute",
    65001: "Address List (old implementation)",
}
