"""
Port-to-service name mapping for ICS and common network services.

Provides human-readable service names for well-known port numbers,
with emphasis on industrial control system protocols.
"""

# ICS protocol ports
_ICS_PORTS = {
    (102, "tcp"): "S7/MMS",
    (502, "tcp"): "Modbus",
    (789, "tcp"): "Crimson v3",
    (1089, "tcp"): "FF HSE",
    (1911, "tcp"): "Niagara Fox",
    (2222, "tcp"): "EtherNet/IP Config",
    (2404, "tcp"): "IEC-104",
    (3671, "udp"): "KNXnet/IP",
    (4000, "tcp"): "Emerson ROC",
    (4840, "tcp"): "OPC-UA",
    (4911, "tcp"): "Niagara Fox TLS",
    (5007, "tcp"): "OSIsoft PI",
    (9600, "tcp"): "FINS/Omron",
    (18245, "tcp"): "GE SRTP",
    (20000, "tcp"): "DNP3",
    (20547, "tcp"): "ProConOS",
    (34962, "udp"): "PROFINET RT",
    (34964, "udp"): "PROFINET DCP",
    (41100, "tcp"): "Siemens HMS",
    (44818, "tcp"): "EtherNet/IP",
    (44818, "udp"): "EtherNet/IP",
    (47808, "udp"): "BACnet",
    (48898, "tcp"): "ADS/TwinCAT",
    (55000, "tcp"): "FL-net",
    (55003, "tcp"): "FL-net",
}

# Building automation ports
_BUILDING_PORTS = {
    (1628, "tcp"): "LonTalk/IP",
    (3671, "udp"): "KNXnet/IP",
    (47808, "udp"): "BACnet",
}

# Common IT service ports
_COMMON_PORTS = {
    (20, "tcp"): "FTP-Data",
    (21, "tcp"): "FTP",
    (22, "tcp"): "SSH",
    (23, "tcp"): "Telnet",
    (25, "tcp"): "SMTP",
    (53, "tcp"): "DNS",
    (53, "udp"): "DNS",
    (67, "udp"): "DHCP-Server",
    (68, "udp"): "DHCP-Client",
    (69, "udp"): "TFTP",
    (80, "tcp"): "HTTP",
    (88, "tcp"): "Kerberos",
    (110, "tcp"): "POP3",
    (123, "udp"): "NTP",
    (135, "tcp"): "MS-RPC",
    (137, "udp"): "NetBIOS-NS",
    (138, "udp"): "NetBIOS-DGM",
    (139, "tcp"): "NetBIOS-SSN",
    (143, "tcp"): "IMAP",
    (161, "udp"): "SNMP",
    (162, "udp"): "SNMP-Trap",
    (389, "tcp"): "LDAP",
    (443, "tcp"): "HTTPS",
    (445, "tcp"): "SMB",
    (465, "tcp"): "SMTPS",
    (514, "udp"): "Syslog",
    (515, "tcp"): "LPD",
    (587, "tcp"): "SMTP-Submit",
    (623, "udp"): "IPMI",
    (636, "tcp"): "LDAPS",
    (993, "tcp"): "IMAPS",
    (995, "tcp"): "POP3S",
    (1433, "tcp"): "MSSQL",
    (1521, "tcp"): "Oracle",
    (1883, "tcp"): "MQTT",
    (2049, "tcp"): "NFS",
    (3306, "tcp"): "MySQL",
    (3389, "tcp"): "RDP",
    (5060, "udp"): "SIP",
    (5061, "tcp"): "SIPS",
    (5432, "tcp"): "PostgreSQL",
    (5672, "tcp"): "AMQP",
    (5900, "tcp"): "VNC",
    (6379, "tcp"): "Redis",
    (8080, "tcp"): "HTTP-Alt",
    (8443, "tcp"): "HTTPS-Alt",
    (8883, "tcp"): "MQTT-TLS",
    (9092, "tcp"): "Kafka",
    (27017, "tcp"): "MongoDB",
}

# Merged lookup table (ICS takes priority over common)
_ALL_PORTS = {**_COMMON_PORTS, **_ICS_PORTS}
