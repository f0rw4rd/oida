"""Common SNMP encoding utilities shared across SNMPv1, v2c, and v3 fuzzers."""

from ..primitives.asn1 import encode_ber_object_identifier


def encode_oid(oid_string: str) -> bytes:
    """Encode OID string to BER format.

    Args:
        oid_string: OID in dotted decimal notation (e.g., "1.3.6.1.2.1")

    Returns:
        BER-encoded OID bytes (complete TLV)
    """
    return encode_ber_object_identifier(oid_string)


def ip_to_bytes(ip_string: str) -> bytes:
    """Convert IP address string to bytes.

    Args:
        ip_string: IPv4 address string (e.g., "192.168.1.1")

    Returns:
        4-byte representation of the IP address

    Raises:
        ValueError: If IP address format is invalid
    """
    parts = ip_string.split(".")
    if len(parts) != 4:
        raise ValueError(f"IPv4 address must have 4 octets, got {len(parts)}")
    octets = []
    for i, p in enumerate(parts):
        try:
            val = int(p)
        except ValueError:
            raise ValueError(f"Invalid octet '{p}' at position {i}")
        if not 0 <= val <= 255:
            raise ValueError(f"Octet {i} value {val} out of range (0-255)")
        octets.append(val)
    return bytes(octets)


def hex_to_bytes(hex_string: str) -> bytes:
    """Convert hex string to bytes.

    Args:
        hex_string: Hexadecimal string (e.g., "8000000001020304")

    Returns:
        Decoded bytes
    """
    return bytes.fromhex(hex_string)


__all__ = ["encode_oid", "ip_to_bytes", "hex_to_bytes"]
