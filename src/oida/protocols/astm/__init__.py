"""
ASTM/LIS Protocol Scanner

Scans ASTM E1381/E1394 (CLSI LIS01/LIS02) laboratory endpoints for:
- Connection testing (ENQ/ACK handshake)
- Record exchange (H, P, O, R, C, Q, L records)
- Instrument/LIS fingerprinting from header records
- Lab test enumeration
- Patient data interaction
- Security assessment (no native auth = security gap)

CLI examples:
    oida astm 192.168.1.100              # Basic connection test
    oida astm 192.168.1.100 --probe-ops  # Probe supported record types
    oida astm 192.168.1.100 --send-query # Send Q record query
    oida astm 192.168.1.100 --enum-tests # Enumerate lab tests
    oida astm 192.168.1.100 --fuzz       # Protocol fuzzing
"""

# Re-export the NXC-style connection class (mixin-based)
from .cli_runner import astm

__all__ = ["astm"]
