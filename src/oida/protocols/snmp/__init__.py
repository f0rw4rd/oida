"""
SNMP Protocol Module

Standalone SNMP scanner for querying network devices via SNMP.
Supports SNMPv1, v2c, v3 with vendor-specific OID enumeration
and host table enumeration (ARP/CAM via ``-e arp`` / ``-e cam``).

CLI examples:
    oida snmp 192.168.1.1                         # Basic SNMPv2c scan
    oida snmp 192.168.1.1 -C private              # Custom community
    oida snmp 192.168.1.1 -e arp,cam              # Enumerate ARP + CAM tables
    oida snmp 192.168.1.1 --snmp-version 3 --snmp-user admin
"""

from .scanner import SNMPScanner, protocol_options, metadata, run, scan_targets
from .nxc_connection import snmp
from .constants import (
    SNMP_OIDS,
    VENDOR_OIDS,
    VENDOR_SPECIFIC_OIDS,
    ENUM_CATEGORIES,
    HOST_RESOURCE_OIDS,
    CREDENTIAL_OIDS,
)

__all__ = [
    "SNMPScanner",
    "snmp",
    "protocol_options",
    "metadata",
    "run",
    "scan_targets",
    "SNMP_OIDS",
    "VENDOR_OIDS",
    "VENDOR_SPECIFIC_OIDS",
    "ENUM_CATEGORIES",
    "HOST_RESOURCE_OIDS",
    "CREDENTIAL_OIDS",
]
