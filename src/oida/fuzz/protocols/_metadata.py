"""
Lightweight fuzz protocol metadata — no fuzzer class imports.

Import this instead of the full protocols package when you only need
PROTOCOL_CATEGORIES or PROTOCOL_TO_CATEGORY (e.g. for `oida fuzz list`).
"""

PROTOCOL_CATEGORIES = {
    "web": {
        "name": "Web Protocols",
        "description": "HTTP, HTTPS, and related web protocols",
        "protocols": ["http", "http2"],
    },
    "email": {
        "name": "Email Protocols",
        "description": "SMTP and email-related protocols",
        "protocols": ["smtp"],
    },
    "file_transfer": {
        "name": "File Transfer",
        "description": "FTP, TFTP, and file transfer protocols",
        "protocols": ["ftp", "tftp"],
    },
    "ics": {
        "name": "Industrial Control Systems",
        "description": "Industrial protocols for SCADA, automation, and control systems",
        "protocols": [
            "modbus",
            "modbus_rtu",
            "iec104",
            "dnp3",
            "bacnet",
            "ethernetip",
            "ads",
            "mms",
            "opcua",
            "s7comm",
            "profinet",
            "ethercat",
            "goose",
            "hart",
            "knx",
            "tase2",
            "can",
        ],
    },
    "iot": {
        "name": "IoT Protocols",
        "description": "Internet of Things and embedded protocols",
        "protocols": ["mqtt", "coap"],
    },
    "network": {
        "name": "Network Infrastructure",
        "description": "DNS, DHCP, NTP, and core network protocols",
        "protocols": [
            "dns",
            "dhcp",
            "dhcpv6",
            "mdns",
            "netbios",
            "ntp",
            "snmpv1",
            "snmpv2c",
            "snmpv3",
        ],
    },
    "remote_access": {
        "name": "Remote Access",
        "description": "VNC and remote desktop protocols",
        "protocols": ["vnc"],
    },
    "layer3": {
        "name": "Network Layer (Layer 3)",
        "description": "IP, ICMP, and IP-multicast protocols",
        "protocols": ["ipv4", "ipv6", "icmp", "icmpv6", "igmp"],
    },
    "layer2": {
        "name": "Data Link Layer (Layer 2)",
        "description": "Ethernet, PPPoE, and link/adaptation-layer protocols",
        "protocols": ["ethernet", "pppoe", "6lowpan"],
    },
    "application": {
        "name": "Application Protocols",
        "description": "Generic application-layer protocols",
        "protocols": ["echo", "daytime"],
    },
    "transport": {
        "name": "Transport Layer",
        "description": "TCP and raw transport protocols",
        "protocols": ["tcp"],
    },
    "mutation": {
        "name": "Mutation Fuzzer",
        "description": "Radamsa-powered mutation fuzzer (use with captured packets as seeds)",
        "protocols": ["mutation"],
    },
    "healthcare": {
        "name": "Healthcare Protocols",
        "description": "HL7, DICOM, and ASTM/LIS protocols for healthcare systems",
        "protocols": ["hl7", "dicom", "astm"],
    },
}

PROTOCOL_TO_CATEGORY = {}
for _category, _data in PROTOCOL_CATEGORIES.items():
    for _protocol in _data["protocols"]:
        PROTOCOL_TO_CATEGORY[_protocol] = _category
