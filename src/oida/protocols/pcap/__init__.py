"""
PCAP Analysis Protocol

Offline analysis of pcap/pcapng capture files:
- Credential extraction (FTP, Telnet, HTTP, LDAP, etc.)
- ICS protocol traffic analysis (Modbus, IEC104, OPC UA, S7, DNP3, etc.)
- DNS hostname extraction
- File carving from HTTP, SMB, FTP, TFTP, DICOM
- Traffic statistics

Uses listeners from oida.pcap.passive (PyShark-based) for streaming
packet analysis across all supported protocol categories.

Usage:
    oida pcap capture.pcap                    # Full analysis
    oida pcap capture.pcap -E                 # File extraction
    oida pcap capture.pcap -p ics             # ICS protocols only
"""

from .scanner import PcapScanner, pcap

__all__ = ["PcapScanner", "pcap"]
