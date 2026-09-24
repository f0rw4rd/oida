"""
Declarative listener registry for PCAP analysis.

Maps listener names to (module_path, class_name, category, tags) for
lazy instantiation and filtering. Categories enable tag-based selection
(e.g. ``--protocols ics`` activates all ICS listeners).

Usage:
    from .listener_registry import resolve_listener_names, create_listeners

    names = resolve_listener_names(protocols=["ics"], quick=False)
    listeners = create_listeners(names)
"""

import importlib
from typing import Any, Dict, List, Optional, Set

from oida.utils.ics_logger import get_module_logger

logger = get_module_logger(__name__)


# ---------------------------------------------------------------------------
# Registry: name -> (module_path, class_name, category, tags)
#
# module_path is relative to oida.pcap
# tags are used for filtering: protocol name, category, and any aliases
# ---------------------------------------------------------------------------

LISTENER_REGISTRY: Dict[str, Dict[str, Any]] = {
    # --- Credential listeners ---
    "ftp": {
        "module": ".ftp",
        "class": "FTPPassiveListener",
        "category": "credential",
        "tags": {"credential", "ftp", "cleartext"},
    },
    "telnet": {
        "module": ".telnet",
        "class": "TelnetPassiveListener",
        "category": "credential",
        "tags": {"credential", "telnet", "cleartext"},
    },
    "imap": {
        "module": ".imap",
        "class": "IMAPPassiveListener",
        "category": "credential",
        "tags": {"credential", "imap", "email"},
    },
    "smtp": {
        "module": ".smtp",
        "class": "SMTPPassiveListener",
        "category": "credential",
        "tags": {"credential", "smtp", "email"},
    },
    "pop3": {
        "module": ".pop3",
        "class": "POP3PassiveListener",
        "category": "credential",
        "tags": {"credential", "pop3", "email"},
    },
    "kerberos": {
        "module": ".kerberos",
        "class": "KerberosPassiveListener",
        "category": "credential",
        "tags": {"credential", "kerberos", "auth"},
    },
    "ntlm": {
        "module": ".ntlm",
        "class": "NTLMPassiveListener",
        "category": "credential",
        "tags": {"credential", "ntlm", "auth"},
    },
    "sip": {
        "module": ".sip",
        "class": "SIPPassiveListener",
        "category": "credential",
        "tags": {"credential", "sip", "voip"},
    },
    "radius": {
        "module": ".radius",
        "class": "RADIUSPassiveListener",
        "category": "credential",
        "tags": {"credential", "radius", "auth"},
    },
    "irc": {
        "module": ".irc",
        "class": "IRCPassiveListener",
        "category": "credential",
        "tags": {"credential", "irc"},
    },
    "tacacs": {
        "module": ".tacacs",
        "class": "TACACSPassiveListener",
        "category": "credential",
        "tags": {"credential", "tacacs", "auth"},
    },
    "rdp": {
        "module": ".rdp",
        "class": "RDPPassiveListener",
        "category": "credential",
        "tags": {"credential", "rdp", "remote"},
    },
    "socks": {
        "module": ".socks",
        "class": "SOCKSPassiveListener",
        "category": "credential",
        "tags": {"credential", "socks", "proxy"},
    },
    "mqtt": {
        "module": ".mqtt",
        "class": "MQTTPassiveListener",
        "category": "credential",
        "tags": {"credential", "mqtt", "iot"},
    },
    "mqttsn": {
        "module": ".mqttsn",
        "class": "MQTTSNPassiveListener",
        "category": "network",
        "tags": {"network", "mqttsn", "mqtt-sn", "iot", "sensor", "constrained"},
    },
    "coap": {
        "module": ".coap",
        "class": "CoAPPassiveListener",
        "category": "network",
        "tags": {"network", "coap", "iot", "constrained"},
    },
    "bfd": {
        "module": ".bfd",
        "class": "BFDPassiveListener",
        "category": "credential",
        "tags": {"credential", "bfd", "network"},
    },
    "pap": {
        "module": ".pap",
        "class": "PAPPassiveListener",
        "category": "credential",
        "tags": {"credential", "pap", "cleartext"},
    },
    "bgp": {
        "module": ".bgp",
        "class": "BGPPassiveListener",
        "category": "credential",
        "tags": {"credential", "bgp", "routing"},
    },
    # --- Database listeners ---
    "pgsql": {
        "module": ".pgsql",
        "class": "PostgreSQLPassiveListener",
        "category": "credential",
        "tags": {"credential", "pgsql", "database", "postgresql"},
    },
    "mysql": {
        "module": ".mysql",
        "class": "MySQLPassiveListener",
        "category": "credential",
        "tags": {"credential", "mysql", "database"},
    },
    "mssql": {
        "module": ".mssql",
        "class": "MSSQLPassiveListener",
        "category": "credential",
        "tags": {"credential", "mssql", "database"},
    },
    # --- Network service listeners ---
    "ldap": {
        "module": ".ldap",
        "class": "LDAPPassiveListener",
        "category": "credential",
        "tags": {"credential", "ldap", "auth"},
    },
    "smb": {
        "module": ".smb",
        "class": "SMBPassiveListener",
        "category": "network",
        "tags": {"credential", "smb", "network"},
    },
    "vnc": {
        "module": ".vnc",
        "class": "VNCPassiveListener",
        "category": "credential",
        "tags": {"credential", "vnc", "remote"},
    },
    # --- Protocol-specific listeners ---
    "tls": {
        "module": ".tls",
        "class": "TLSPassiveListener",
        "category": "network",
        "tags": {"network", "tls", "crypto", "certificates"},
    },
    "dns": {
        "module": ".dns",
        "class": "DNSPassiveListener",
        "category": "network",
        "tags": {"network", "dns"},
    },
    "http": {
        "module": ".http",
        "class": "HTTPPassiveListener",
        "category": "network",
        "tags": {"credential", "http", "network"},
    },
    "snmp": {
        "module": ".snmp",
        "class": "SNMPPassiveListener",
        "category": "network",
        "tags": {"credential", "snmp", "network"},
    },
    # --- ICS listeners ---
    "modbus": {
        "module": ".modbus",
        "class": "ModbusPassiveListener",
        "category": "ics",
        "tags": {"ics", "modbus"},
    },
    "egd": {
        "module": ".egd",
        "class": "EGDPassiveListener",
        "category": "ics",
        "tags": {"ics", "egd", "ge", "plc", "power"},
    },
    "selfm": {
        "module": ".selfm",
        "class": "SELFMPassiveListener",
        "category": "ics",
        "tags": {"ics", "selfm", "sel", "schweitzer", "relay", "power", "substation"},
    },
    "tte": {
        "module": ".tte",
        "class": "TTEPassiveListener",
        "category": "ics",
        "tags": {"ics", "tte", "ttethernet", "as6802", "tsn", "deterministic"},
    },
    "rtps": {
        "module": ".rtps",
        "class": "RTPSPassiveListener",
        "category": "ics",
        "tags": {"ics", "rtps", "dds", "pubsub", "middleware", "ros2"},
    },
    "ieee1722": {
        "module": ".ieee1722",
        "class": "IEEE1722PassiveListener",
        "category": "ics",
        "tags": {"ics", "ieee1722", "avtp", "avb", "tsn", "automotive"},
    },
    "iec104": {
        "module": ".iec104",
        "class": "IEC104PassiveListener",
        "category": "ics",
        "tags": {"ics", "iec104"},
    },
    "iec101": {
        "module": ".iec101",
        "class": "IEC101PassiveListener",
        "category": "ics",
        "tags": {"ics", "iec101", "telecontrol", "power"},
    },
    "iec103": {
        "module": ".iec103",
        "class": "IEC103PassiveListener",
        "category": "ics",
        "tags": {"ics", "iec103", "protection", "power", "substation"},
    },
    "synchrophasor": {
        "module": ".synchrophasor",
        "class": "SynchrophasorPassiveListener",
        "category": "ics",
        "tags": {"ics", "synchrophasor", "c37118", "pmu", "pdc", "power"},
    },
    "opcua": {
        "module": ".opcua",
        "class": "OPCUAPassiveListener",
        "category": "ics",
        "tags": {"ics", "opcua"},
    },
    "opcda": {
        "module": ".opcda",
        "class": "OPCDAPassiveListener",
        "category": "ics",
        "tags": {"ics", "opcda", "opc", "dcom", "scada", "hmi"},
    },
    "s7comm": {
        "module": ".s7comm",
        "class": "S7commPassiveListener",
        "category": "ics",
        "tags": {"ics", "s7comm", "s7", "siemens"},
    },
    "fins": {
        "module": ".fins",
        "class": "FINSPassiveListener",
        "category": "ics",
        "tags": {"ics", "fins", "omron"},
    },
    "mms": {
        "module": ".mms",
        "class": "MMSPassiveListener",
        "category": "ics",
        "tags": {"ics", "mms", "iec61850"},
    },
    "dnp3": {
        "module": ".dnp3",
        "class": "DNP3PassiveListener",
        "category": "ics",
        "tags": {"ics", "dnp3"},
    },
    "bacnet": {
        "module": ".bacnet",
        "class": "BACnetPassiveListener",
        "category": "ics",
        "tags": {"ics", "bacnet"},
    },
    "enip": {
        "module": ".enip",
        "class": "EtherNetIPPassiveListener",
        "category": "ics",
        "tags": {"ics", "enip", "ethernet/ip", "cip"},
    },
    "ads": {
        "module": ".ads",
        "class": "ADSPassiveListener",
        "category": "ics",
        "tags": {"ics", "ads", "ams", "beckhoff", "twincat"},
    },
    "goose": {
        "module": ".goose",
        "class": "GOOSEPassiveListener",
        "category": "ics",
        "tags": {"ics", "goose", "iec61850"},
    },
    "rgoose": {
        "module": ".rgoose",
        "class": "RGOOSEPassiveListener",
        "category": "ics",
        "tags": {"ics", "rgoose", "r-goose", "iec61850", "goose"},
    },
    "cipsafety": {
        "module": ".cipsafety",
        "class": "CIPSafetyPassiveListener",
        "category": "ics",
        "tags": {"ics", "cipsafety", "cip", "enip", "safety"},
    },
    "sv": {
        "module": ".sv",
        "class": "SVPassiveListener",
        "category": "ics",
        "tags": {"ics", "sv", "iec61850", "sampled_values"},
    },
    "profinet": {
        "module": ".profinet",
        "class": "PROFINETPassiveListener",
        "category": "ics",
        "tags": {"ics", "profinet", "pn", "siemens"},
    },
    "ethercat": {
        "module": ".ethercat",
        "class": "EtherCATPassiveListener",
        "category": "ics",
        "tags": {"ics", "ethercat", "beckhoff", "fieldbus"},
    },
    "hartip": {
        "module": ".hartip",
        "class": "HARTIPPassiveListener",
        "category": "ics",
        "tags": {"ics", "hartip", "hart"},
    },
    "knx": {
        "module": ".knx",
        "class": "KNXPassiveListener",
        "category": "ics",
        "tags": {"ics", "knx", "knxip", "building"},
    },
    "can": {
        "module": ".can",
        "class": "CANPassiveListener",
        "category": "ics",
        "tags": {"ics", "can", "canfd", "caneth", "fieldbus"},
    },
    "canopen": {
        "module": ".canopen",
        "class": "CANopenPassiveListener",
        "category": "ics",
        "tags": {"ics", "canopen", "can", "fieldbus", "automation"},
    },
    "j1939": {
        "module": ".j1939",
        "class": "J1939PassiveListener",
        "category": "ics",
        "tags": {"ics", "j1939", "can", "vehicle", "automotive"},
    },
    "epl": {
        "module": ".epl",
        "class": "EPLPassiveListener",
        "category": "ics",
        "tags": {"ics", "epl", "powerlink", "fieldbus"},
    },
    "sercos": {
        "module": ".sercos",
        "class": "SERCOSPassiveListener",
        "category": "ics",
        "tags": {"ics", "sercos", "sercosiii", "fieldbus"},
    },
    "ff_hse": {
        "module": ".ff_hse",
        "class": "FFHSEPassiveListener",
        "category": "ics",
        "tags": {"ics", "ff_hse", "foundation_fieldbus", "fieldbus"},
    },
    "lontalk": {
        "module": ".lontalk",
        "class": "LonTalkPassiveListener",
        "category": "ics",
        "tags": {"ics", "lontalk", "lon", "building"},
    },
    "pcom": {
        "module": ".pcom",
        "class": "PCOMPassiveListener",
        "category": "ics",
        "tags": {"ics", "pcom", "unitronics", "plc"},
    },
    "devicenet": {
        "module": ".devicenet",
        "class": "DeviceNetPassiveListener",
        "category": "ics",
        "tags": {"ics", "devicenet", "cip", "can", "fieldbus"},
    },
    "nmea0183": {
        "module": ".nmea0183",
        "class": "NMEA0183PassiveListener",
        "category": "ics",
        "tags": {"ics", "nmea", "nmea0183", "maritime", "gps"},
    },
    "dicom": {
        "module": ".dicom",
        "class": "DICOMPassiveListener",
        "category": "ics",
        "tags": {"ics", "dicom", "medical", "healthcare"},
    },
    "hl7": {
        "module": ".hl7",
        "class": "HL7PassiveListener",
        "category": "ics",
        "tags": {"ics", "hl7", "medical", "healthcare"},
    },
    "hsr": {
        "module": ".hsr",
        "class": "HSRPassiveListener",
        "category": "ics",
        "tags": {"ics", "hsr", "redundancy", "iec62439", "substation"},
    },
    "prp": {
        "module": ".prp",
        "class": "PRPPassiveListener",
        "category": "ics",
        "tags": {"ics", "prp", "redundancy", "iec62439", "substation"},
    },
    "cotp": {
        "module": ".cotp",
        "class": "COTPPassiveListener",
        "category": "ics",
        "tags": {"ics", "cotp", "tpkt", "iso", "transport"},
    },
    "c1222": {
        "module": ".c1222",
        "class": "C1222PassiveListener",
        "category": "ics",
        "tags": {"ics", "c1222", "ami", "metering", "smartgrid"},
    },
    "ptp": {
        "module": ".ptp",
        "class": "PTPPassiveListener",
        "category": "ics",
        "tags": {"ics", "ptp", "ieee1588", "time", "sync"},
    },
    "opensafety": {
        "module": ".opensafety",
        "class": "OpenSAFETYPassiveListener",
        "category": "ics",
        "tags": {"ics", "opensafety", "safety", "sil3"},
    },
    # --- Routing protocol listeners ---
    "ospf": {
        "module": ".ospf",
        "class": "OSPFPassiveListener",
        "category": "routing",
        "tags": {"routing", "ospf"},
    },
    "eigrp": {
        "module": ".eigrp",
        "class": "EIGRPPassiveListener",
        "category": "routing",
        "tags": {"routing", "eigrp"},
    },
    "rip": {
        "module": ".rip",
        "class": "RIPPassiveListener",
        "category": "routing",
        "tags": {"routing", "rip", "credential"},
    },
    "pim": {
        "module": ".pim",
        "class": "PIMPassiveListener",
        "category": "routing",
        "tags": {"routing", "pim", "multicast"},
    },
    # --- FHRP listeners ---
    # A single HSRPPassiveListener handles both HSRPv1 and HSRPv2 (it version-
    # switches internally). Do NOT also register "hsrpv2" -> the same class:
    # default resolution would instantiate both, feed every HSRP packet to each,
    # and duplicate every interaction/credential/hash row in the merged output.
    "hsrp": {
        "module": ".hsrp",
        "class": "HSRPPassiveListener",
        "category": "fhrp",
        "tags": {"fhrp", "hsrp", "hsrpv2", "credential"},
    },
    "glbp": {
        "module": ".glbp",
        "class": "GLBPPassiveListener",
        "category": "fhrp",
        "tags": {"fhrp", "glbp"},
    },
    "vrrp": {
        "module": ".vrrp",
        "class": "VRRPPassiveListener",
        "category": "fhrp",
        "tags": {"fhrp", "vrrp", "credential"},
    },
    # --- File transfer ---
    "tftp": {
        "module": ".tftp",
        "class": "TFTPPassiveListener",
        "category": "network",
        "tags": {"network", "tftp", "file_transfer"},
    },
    # --- Multicast ---
    "igmp": {
        "module": ".igmp",
        "class": "IGMPPassiveListener",
        "category": "network",
        "tags": {"network", "igmp", "multicast"},
    },
    # --- Discovery/broadcast protocols ---
    "lldp": {
        "module": ".lldp",
        "class": "LLDPPassiveListener",
        "category": "discovery",
        "tags": {"discovery", "lldp", "network", "l2"},
    },
    "cdp": {
        "module": ".cdp",
        "class": "CDPPassiveListener",
        "category": "discovery",
        "tags": {"discovery", "cdp", "network", "cisco", "l2"},
    },
    "stp": {
        "module": ".stp",
        "class": "STPPassiveListener",
        "category": "discovery",
        "tags": {"discovery", "stp", "rstp", "network", "l2"},
    },
    "dtp": {
        "module": ".dtp",
        "class": "DTPPassiveListener",
        "category": "discovery",
        "tags": {"discovery", "dtp", "network", "cisco", "l2", "trunk"},
    },
    "vtp": {
        "module": ".vtp",
        "class": "VTPPassiveListener",
        "category": "discovery",
        "tags": {"discovery", "vtp", "network", "cisco", "l2", "vlan"},
    },
    "ssdp": {
        "module": ".ssdp",
        "class": "SSDPPassiveListener",
        "category": "discovery",
        "tags": {"discovery", "ssdp", "upnp", "network"},
    },
    "mdns": {
        "module": ".mdns",
        "class": "MDNSPassiveListener",
        "category": "discovery",
        "tags": {"discovery", "mdns", "bonjour", "dns-sd", "network"},
    },
    "dhcp": {
        "module": ".dhcp",
        "class": "DHCPPassiveListener",
        "category": "discovery",
        "tags": {"discovery", "dhcp", "bootp", "network"},
    },
    # --- NEW: Network infrastructure listeners ---
    "ntp": {
        "module": ".ntp",
        "class": "NTPPassiveListener",
        "category": "network",
        "tags": {"network", "ntp", "time"},
    },
    "ipmi": {
        "module": ".ipmi",
        "class": "IPMIPassiveListener",
        "category": "network",
        "tags": {"network", "ipmi", "bmc", "oob"},
    },
    "rpcbind": {
        "module": ".rpcbind",
        "class": "RPCBindPassiveListener",
        "category": "network",
        "tags": {"network", "rpcbind", "portmap", "rpc"},
    },
    "nfs": {
        "module": ".nfs",
        "class": "NFSPassiveListener",
        "category": "network",
        "tags": {"network", "nfs", "storage", "file_transfer"},
    },
    "msrpc": {
        "module": ".msrpc",
        "class": "MSRPCPassiveListener",
        "category": "network",
        "tags": {"network", "msrpc", "dcerpc", "windows"},
    },
    "ipsec": {
        "module": ".ipsec",
        "class": "IPsecPassiveListener",
        "category": "network",
        "tags": {"network", "ipsec", "ike", "isakmp", "vpn"},
    },
    "iscsi": {
        "module": ".iscsi",
        "class": "ISCSIPassiveListener",
        "category": "network",
        "tags": {"network", "iscsi", "storage", "san"},
    },
    # --- NEW: Discovery listeners ---
    "netbios": {
        "module": ".netbios",
        "class": "NetBIOSPassiveListener",
        "category": "discovery",
        "tags": {"discovery", "netbios", "nbns", "windows"},
    },
    "wsdiscovery": {
        "module": ".wsdiscovery",
        "class": "WSDiscoveryPassiveListener",
        "category": "discovery",
        "tags": {"discovery", "wsdiscovery", "onvif", "iot"},
    },
    # --- NEW: Messaging listeners ---
    "amqp": {
        "module": ".amqp",
        "class": "AMQPPassiveListener",
        "category": "network",
        "tags": {"network", "amqp", "messaging", "rabbitmq"},
    },
    "ibmmq": {
        "module": ".ibmmq",
        "class": "IBMMQPassiveListener",
        "category": "network",
        "tags": {"network", "ibmmq", "mq", "messaging"},
    },
    # --- NEW: Database listeners ---
    "mongodb": {
        "module": ".mongodb",
        "class": "MongoDBPassiveListener",
        "category": "network",
        "tags": {"network", "mongodb", "database", "nosql"},
    },
    "redis": {
        "module": ".redis",
        "class": "RedisPassiveListener",
        "category": "network",
        "tags": {"network", "redis", "database", "cache"},
    },
    "memcached": {
        "module": ".memcached",
        "class": "MemcachedPassiveListener",
        "category": "network",
        "tags": {"network", "memcached", "cache"},
    },
    "tns": {
        "module": ".tns",
        "class": "TNSPassiveListener",
        "category": "network",
        "tags": {"network", "tns", "oracle", "database"},
    },
    # --- NEW: Streaming / camera ---
    "rtsp": {
        "module": ".rtsp",
        "class": "RTSPPassiveListener",
        "category": "network",
        "tags": {"network", "rtsp", "streaming", "camera", "surveillance"},
    },
    # --- NEW: Cisco ---
    "smartinstall": {
        "module": ".smartinstall",
        "class": "SmartInstallPassiveListener",
        "category": "network",
        "tags": {"network", "smartinstall", "cisco"},
    },
    # --- NEW: Printing ---
    "ipp": {
        "module": ".ipp",
        "class": "IPPPassiveListener",
        "category": "network",
        "tags": {"network", "ipp", "printer", "cups"},
    },
    "pjl": {
        "module": ".pjl",
        "class": "PJLPassiveListener",
        "category": "network",
        "tags": {"network", "pjl", "printer", "hp"},
    },
    # --- NEW: Remote display ---
    "x11": {
        "module": ".x11",
        "class": "X11PassiveListener",
        "category": "network",
        "tags": {"network", "x11", "display", "remote"},
    },
    # --- NEW: Java / application server ---
    "ajp": {
        "module": ".ajp",
        "class": "AJPPassiveListener",
        "category": "network",
        "tags": {"network", "ajp", "tomcat", "java"},
    },
    "rmi": {
        "module": ".rmi",
        "class": "RMIPassiveListener",
        "category": "network",
        "tags": {"network", "rmi", "java", "jndi"},
    },
    # --- NEW: File transfer ---
    "rsync": {
        "module": ".rsync",
        "class": "RsyncPassiveListener",
        "category": "network",
        "tags": {"network", "rsync", "file_transfer"},
    },
}

# Quick-scan preset: core protocols for fast overview
QUICK_LISTENERS = {
    "dns",
    "tls",
    "http",
    "ftp",
    "telnet",
    "smb",
    "snmp",
    "modbus",
    "iec104",
    "opcua",
    "s7comm",
    "dnp3",
    "enip",
    "bacnet",
}

# All valid category names (derived from the registry)
CATEGORIES = {info["category"] for info in LISTENER_REGISTRY.values()}


def list_listeners() -> List[Dict[str, Any]]:
    """Return a sorted list of all registered listeners with metadata."""
    result = []
    for name, info in sorted(LISTENER_REGISTRY.items()):
        result.append(
            {
                "name": name,
                "class": info["class"],
                "category": info["category"],
                "tags": sorted(info["tags"]),
            }
        )
    return result


def resolve_listener_names(
    protocols: Optional[List[str]] = None,
    category: Optional[List[str]] = None,
    quick: bool = False,
    exclude: Optional[List[str]] = None,
    logger=logger,
) -> Set[str]:
    """Resolve a set of listener names from filter criteria.

    Args:
        protocols: Names or tags to include (e.g. ["ics", "ftp", "modbus"])
        category: Categories to include (e.g. ["ics", "credential"])
        quick: Use quick-scan preset (overrides protocols/category)
        exclude: Names or tags to exclude

    Returns:
        Set of listener names to instantiate
    """
    names: Set[str] = set()
    if quick:
        logger.debug(
            "resolve_listener_names: using quick preset (%d listeners)", len(QUICK_LISTENERS)
        )
        names = set(QUICK_LISTENERS)
    elif protocols or category:
        if protocols:
            for p in protocols:
                p_lower = p.lower().strip()
                matched = []
                for lname, info in LISTENER_REGISTRY.items():
                    if p_lower == lname or p_lower in info["tags"]:
                        names.add(lname)
                        matched.append(lname)
                logger.debug("resolve_listener_names: protocol filter '%s' matched: %s", p, matched)
        if category:
            for cat in category:
                cat_lower = cat.lower().strip()
                matched = []
                for lname, info in LISTENER_REGISTRY.items():
                    if info["category"] == cat_lower:
                        names.add(lname)
                        matched.append(lname)
                logger.debug(
                    "resolve_listener_names: category filter '%s' matched: %s", cat, matched
                )
    else:
        logger.debug(
            "resolve_listener_names: no filters, using all %d listeners", len(LISTENER_REGISTRY)
        )
        names = set(LISTENER_REGISTRY.keys())

    if exclude:
        excluded: Set[str] = set()
        for ex in exclude:
            ex_lower = ex.lower().strip()
            for lname, info in LISTENER_REGISTRY.items():
                if ex_lower == lname or ex_lower in info["tags"] or ex_lower == info["category"]:
                    excluded.add(lname)
        logger.debug(
            "resolve_listener_names: excluded %d listeners: %s", len(excluded), sorted(excluded)
        )
        names -= excluded

    logger.debug("resolve_listener_names: final set has %d listeners", len(names))
    return names


def create_listeners(names: Set[str], logger=logger) -> Dict[str, Any]:
    """Instantiate listeners by name via lazy importlib.

    Returns:
        Dict mapping listener name to instantiated listener object.
        Listeners that fail to instantiate are skipped, with the failure
        surfaced via a warning (not just a debug log) so an operator does not
        mistake a partially-loaded listener set for full protocol coverage.
    """
    listeners = {}
    failed = []
    for name in sorted(names):
        info = LISTENER_REGISTRY.get(name)
        if not info:
            logger.debug("create_listeners: unknown listener '%s'", name)
            continue
        try:
            module = importlib.import_module(info["module"], "oida.pcap")
            cls = getattr(module, info["class"])
            listeners[name] = cls(interface="pcap", nxc_logger=logger)
            logger.debug("create_listeners: registered %s (%s)", name, info["class"])
        except Exception as e:
            failed.append(name)
            logger.debug("create_listeners: failed to create %s (%s): %s", name, info["class"], e)

    if failed:
        logger.warning(
            "create_listeners: %d/%d listeners failed to load: %s",
            len(failed),
            len(names),
            ", ".join(failed),
        )
    logger.debug("create_listeners: %d listeners ready", len(listeners))
    return listeners
