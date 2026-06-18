#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
EtherNet/IP Protocol Constants

Defines EtherNet/IP encapsulation commands and CIP class definitions.
"""

# =============================================================================
# EtherNet/IP Encapsulation Commands
# =============================================================================

ENIP_CMD_LIST_SERVICES = 0x0004
ENIP_CMD_LIST_IDENTITY = 0x0063
ENIP_CMD_LIST_INTERFACES = 0x0064
ENIP_CMD_REGISTER_SESSION = 0x0065
ENIP_CMD_UNREGISTER_SESSION = 0x0066
ENIP_CMD_SEND_RR_DATA = 0x006F
ENIP_CMD_SEND_UNIT_DATA = 0x0070

# =============================================================================
# CIP Object Classes
# =============================================================================

# CIP Security related classes
CIP_SECURITY_CLASSES = {
    0x5D: "CIP Security",
    0x5E: "EtherNet/IP Security",
    0x5F: "Certificate Management",
    0x60: "Authority",
    0x61: "Password Authenticator",
    0x62: "Certificate Authenticator",
}

# CIP General Status Codes (Vol 1, Appendix B)
CIP_GENERAL_STATUS = {
    0x00: "Success",
    0x01: "Connection failure",
    0x02: "Resource unavailable",
    0x03: "Invalid parameter value",
    0x04: "Path segment error",
    0x05: "Path destination unknown",
    0x06: "Partial transfer",
    0x08: "Service not supported",
    0x09: "Invalid attribute value",
    0x0A: "Attribute list error",
    0x0B: "Already in requested mode/state",
    0x0C: "Object state conflict",
    0x0D: "Object already exists",
    0x0E: "Attribute not settable",
    0x0F: "Privilege violation",
    0x10: "Device state conflict",
    0x11: "Reply data too large",
    0x12: "Fragmentation of primitive value",
    0x13: "Not enough data",
    0x14: "Attribute not supported",
    0x15: "Too much data",
    0x16: "Object does not exist",
    0x17: "Service fragmentation sequence not in progress",
    0x18: "No stored attribute data",
    0x19: "Store operation failure",
    0x1A: "Routing failure, request packet too large",
    0x1B: "Routing failure, response packet too large",
    0x1C: "Missing attribute list entry data",
    0x1D: "Invalid attribute value list",
    0x1E: "Embedded service error",
    0x1F: "Vendor specific error",
    0x20: "Invalid parameter",
    0x21: "Write-once value or medium already written",
    0x22: "Invalid reply received",
    0x25: "Key failure in path",
    0x26: "Path size invalid",
    0x27: "Unexpected attribute in list",
    0x28: "Invalid Member ID",
    0x29: "Member not settable",
    0x2A: "Group 2 only server general failure",
    0xFF: "Object specific error (see extended status)",
}

__all__ = [
    # ENIP Commands
    "ENIP_CMD_LIST_SERVICES",
    "ENIP_CMD_LIST_IDENTITY",
    "ENIP_CMD_LIST_INTERFACES",
    "ENIP_CMD_REGISTER_SESSION",
    "ENIP_CMD_UNREGISTER_SESSION",
    "ENIP_CMD_SEND_RR_DATA",
    "ENIP_CMD_SEND_UNIT_DATA",
    # CIP Classes
    "CIP_SECURITY_CLASSES",
    # CIP Status Codes
    "CIP_GENERAL_STATUS",
]
