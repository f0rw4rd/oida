"""
PCAP passive protocol traffic analysis.

PyShark/tshark-based and scapy-based passive listeners for analyzing
point-to-point protocol traffic from live capture. PCAP analysis is
inherently passive, so these listeners live directly under ``oida.pcap``;
the ``oida pcap`` CLI command (``protocols/pcap/``) drives them.
"""

# Lazy import mapping: attribute name -> (module, name)
_LAZY_IMPORTS = {
    # Routing protocols
    "OSPFPassiveListener": (".ospf", "OSPFPassiveListener"),
    "EIGRPPassiveListener": (".eigrp", "EIGRPPassiveListener"),
    "RIPPassiveListener": (".rip", "RIPPassiveListener"),
    "RIPCredential": (".rip", "RIPCredential"),
    "PIMPassiveListener": (".pim", "PIMPassiveListener"),
    # FHRP protocols
    "HSRPPassiveListener": (".hsrp", "HSRPPassiveListener"),
    "HSRPv2PassiveListener": (".hsrp", "HSRPv2PassiveListener"),
    "GLBPPassiveListener": (".glbp", "GLBPPassiveListener"),
    "VRRPPassiveListener": (".vrrp", "VRRPPassiveListener"),
    "VRRPCredential": (".vrrp", "VRRPCredential"),
    # Multicast
    "IGMPPassiveListener": (".igmp", "IGMPPassiveListener"),
    # Credential listeners (PyShark-based)
    "FTPPassiveListener": (".ftp", "FTPPassiveListener"),
    "TelnetPassiveListener": (".telnet", "TelnetPassiveListener"),
    "IMAPPassiveListener": (".imap", "IMAPPassiveListener"),
    "SMTPPassiveListener": (".smtp", "SMTPPassiveListener"),
    "POP3PassiveListener": (".pop3", "POP3PassiveListener"),
    "POP3Credential": (".pop3", "POP3Credential"),
    "KerberosPassiveListener": (".kerberos", "KerberosPassiveListener"),
    "NTLMPassiveListener": (".ntlm", "NTLMPassiveListener"),
    "SIPPassiveListener": (".sip", "SIPPassiveListener"),
    "SIPDigestCredential": (".sip", "SIPDigestCredential"),
    "RADIUSPassiveListener": (".radius", "RADIUSPassiveListener"),
    "RADIUSCredential": (".radius", "RADIUSCredential"),
    "IRCPassiveListener": (".irc", "IRCPassiveListener"),
    "IRCCredential": (".irc", "IRCCredential"),
    "TACACSPassiveListener": (".tacacs", "TACACSPassiveListener"),
    "TACACSCredential": (".tacacs", "TACACSCredential"),
    "RDPPassiveListener": (".rdp", "RDPPassiveListener"),
    "RDPCredential": (".rdp", "RDPCredential"),
    "SOCKSPassiveListener": (".socks", "SOCKSPassiveListener"),
    "SOCKSCredential": (".socks", "SOCKSCredential"),
    "MQTTPassiveListener": (".mqtt", "MQTTPassiveListener"),
    "MQTTCredential": (".mqtt", "MQTTCredential"),
    "BFDPassiveListener": (".bfd", "BFDPassiveListener"),
    "BFDCredential": (".bfd", "BFDCredential"),
    "PAPPassiveListener": (".pap", "PAPPassiveListener"),
    "PAPCredential": (".pap", "PAPCredential"),
    "BGPPassiveListener": (".bgp", "BGPPassiveListener"),
    "BGPCredential": (".bgp", "BGPCredential"),
    # Database listeners
    "PostgreSQLPassiveListener": (".pgsql", "PostgreSQLPassiveListener"),
    "PostgreSQLCredential": (".pgsql", "PostgreSQLCredential"),
    "MySQLPassiveListener": (".mysql", "MySQLPassiveListener"),
    "MySQLCredential": (".mysql", "MySQLCredential"),
    "MSSQLPassiveListener": (".mssql", "MSSQLPassiveListener"),
    "MSSQLCredential": (".mssql", "MSSQLCredential"),
    # Network service listeners
    "LDAPPassiveListener": (".ldap", "LDAPPassiveListener"),
    "LDAPCredential": (".ldap", "LDAPCredential"),
    "SMBPassiveListener": (".smb", "SMBPassiveListener"),
    "VNCPassiveListener": (".vnc", "VNCPassiveListener"),
    "VNCCredential": (".vnc", "VNCCredential"),
    # Protocol-specific listeners
    "TLSPassiveListener": (".tls", "TLSPassiveListener"),
    "DNSPassiveListener": (".dns", "DNSPassiveListener"),
    "HTTPPassiveListener": (".http", "HTTPPassiveListener"),
    "SNMPPassiveListener": (".snmp", "SNMPPassiveListener"),
    "SNMPCredential": (".snmp", "SNMPCredential"),
    # ICS listeners
    "ModbusPassiveListener": (".modbus", "ModbusPassiveListener"),
    "MQTTSNPassiveListener": (".mqttsn", "MQTTSNPassiveListener"),
    "EGDPassiveListener": (".egd", "EGDPassiveListener"),
    "SELFMPassiveListener": (".selfm", "SELFMPassiveListener"),
    "TTEPassiveListener": (".tte", "TTEPassiveListener"),
    "RTPSPassiveListener": (".rtps", "RTPSPassiveListener"),
    "IEEE1722PassiveListener": (".ieee1722", "IEEE1722PassiveListener"),
    "IEC104PassiveListener": (".iec104", "IEC104PassiveListener"),
    "IEC101PassiveListener": (".iec101", "IEC101PassiveListener"),
    "IEC103PassiveListener": (".iec103", "IEC103PassiveListener"),
    "SynchrophasorPassiveListener": (".synchrophasor", "SynchrophasorPassiveListener"),
    "OPCUAPassiveListener": (".opcua", "OPCUAPassiveListener"),
    "OPCDAPassiveListener": (".opcda", "OPCDAPassiveListener"),
    "S7commPassiveListener": (".s7comm", "S7commPassiveListener"),
    "S7commCredential": (".s7comm", "S7commCredential"),
    "FINSPassiveListener": (".fins", "FINSPassiveListener"),
    "FINSCredential": (".fins", "FINSCredential"),
    "MMSPassiveListener": (".mms", "MMSPassiveListener"),
    "MMSCredential": (".mms", "MMSCredential"),
    "DNP3PassiveListener": (".dnp3", "DNP3PassiveListener"),
    "BACnetPassiveListener": (".bacnet", "BACnetPassiveListener"),
    "EtherNetIPPassiveListener": (".enip", "EtherNetIPPassiveListener"),
    "ADSPassiveListener": (".ads", "ADSPassiveListener"),
    "GOOSEPassiveListener": (".goose", "GOOSEPassiveListener"),
    "RGOOSEPassiveListener": (".rgoose", "RGOOSEPassiveListener"),
    "CIPSafetyPassiveListener": (".cipsafety", "CIPSafetyPassiveListener"),
    "CoAPPassiveListener": (".coap", "CoAPPassiveListener"),
    "SVPassiveListener": (".sv", "SVPassiveListener"),
    "PROFINETPassiveListener": (".profinet", "PROFINETPassiveListener"),
    "EtherCATPassiveListener": (".ethercat", "EtherCATPassiveListener"),
    "KNXPassiveListener": (".knx", "KNXPassiveListener"),
    "HARTIPPassiveListener": (".hartip", "HARTIPPassiveListener"),
    "CANPassiveListener": (".can", "CANPassiveListener"),
    "CANopenPassiveListener": (".canopen", "CANopenPassiveListener"),
    "J1939PassiveListener": (".j1939", "J1939PassiveListener"),
    "EPLPassiveListener": (".epl", "EPLPassiveListener"),
    "SERCOSPassiveListener": (".sercos", "SERCOSPassiveListener"),
    "FFHSEPassiveListener": (".ff_hse", "FFHSEPassiveListener"),
    "LonTalkPassiveListener": (".lontalk", "LonTalkPassiveListener"),
    "PCOMPassiveListener": (".pcom", "PCOMPassiveListener"),
    "DeviceNetPassiveListener": (".devicenet", "DeviceNetPassiveListener"),
    "NMEA0183PassiveListener": (".nmea0183", "NMEA0183PassiveListener"),
    "DICOMPassiveListener": (".dicom", "DICOMPassiveListener"),
    "HL7PassiveListener": (".hl7", "HL7PassiveListener"),
    "HSRPassiveListener": (".hsr", "HSRPassiveListener"),
    "PRPPassiveListener": (".prp", "PRPPassiveListener"),
    "COTPPassiveListener": (".cotp", "COTPPassiveListener"),
    "C1222PassiveListener": (".c1222", "C1222PassiveListener"),
    "PTPPassiveListener": (".ptp", "PTPPassiveListener"),
    "OpenSAFETYPassiveListener": (".opensafety", "OpenSAFETYPassiveListener"),
    # Interaction tracking infrastructure
    "ProtocolInteraction": (".pyshark_base", "ProtocolInteraction"),
    # File transfer
    "TFTPPassiveListener": (".tftp", "TFTPPassiveListener"),
    # File carving
    "FileCarvingListener": (".file_carving", "FileCarvingListener"),
    # Discovery/broadcast protocol listeners
    "LLDPPassiveListener": (".lldp", "LLDPPassiveListener"),
    "CDPPassiveListener": (".cdp", "CDPPassiveListener"),
    "STPPassiveListener": (".stp", "STPPassiveListener"),
    "SSDPPassiveListener": (".ssdp", "SSDPPassiveListener"),
    "MDNSPassiveListener": (".mdns", "MDNSPassiveListener"),
    "DHCPPassiveListener": (".dhcp", "DHCPPassiveListener"),
}


def __getattr__(name: str):
    if name in _LAZY_IMPORTS:
        module_path, attr_name = _LAZY_IMPORTS[name]
        import importlib

        module = importlib.import_module(module_path, __name__)
        value = getattr(module, attr_name)
        globals()[name] = value
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__():
    return list(globals().keys()) + list(_LAZY_IMPORTS.keys())


__all__ = list(_LAZY_IMPORTS.keys())
