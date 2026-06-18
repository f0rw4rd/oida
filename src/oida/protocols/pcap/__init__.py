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

_LAZY_IMPORTS = {
    "PcapScanner": (".scanner", "PcapScanner"),
    "pcap": (".scanner", "pcap"),
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
