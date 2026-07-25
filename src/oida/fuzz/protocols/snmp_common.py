"""Common SNMP encoding utilities shared across SNMPv1, v2c, and v3 fuzzers."""

from typing import List

from ..primitives.asn1 import encode_ber_object_identifier
from ..primitives.asn1_blocks import encode_length as _encode_ber_length


# ASN.1/BER length-of-length ("long form") mutation octets.
#
# A definite-form BER length is either short form (one octet, 0-127) or long
# form: a leading octet 0x8N whose low nibble N counts how many length octets
# follow. The auto-computed Size / BERSize primitives used elsewhere in the
# SNMP fuzzers only ever emit the *correct* short/long form, so the length-of-
# length machinery is never mutated. These constants are raw length fields
# (the bytes that sit between a TLV tag and its value) that are individually
# malformed the way real BER parsers mishandle them:
#
#   0x81 0xFF            long form, 1 length octet, declares 255 bytes
#   0x82 0xFF 0xFF       long form, 2 length octets, declares 65535 bytes
#   0x84 0xFF..0xFF      long form, 4 length octets, declares ~4 GiB
#   0x80                 indefinite form (illegal for a primitive TLV)
#
# These are exactly the parse paths behind CVE-2019-9162 (net-snmp),
# CVE-2020-14934 (Contiki-NG), CVE-2015-5621 (net-snmp) and CVE-2022-24805
# (Linux kernel BER decoder). The first entry begins with 0x81 so a plain
# (unmutated) render already carries a long-form length octet.
BER_LENGTH_OF_LENGTH_MUTATIONS = [
    b"\x81\xff",  # 1-octet long form, over-declared (255 vs actual)
    b"\x82\xff\xff",  # 2-octet long form, over-declared (65535)
    b"\x84\xff\xff\xff\xff",  # 4-octet length-of-length, ~4 GiB
    b"\x80",  # indefinite form (illegal for a primitive)
]


def encode_oid(oid_string: str) -> bytes:
    """Encode OID string to BER format.

    Args:
        oid_string: OID in dotted decimal notation (e.g., "1.3.6.1.2.1")

    Returns:
        BER-encoded OID bytes (complete TLV)
    """
    return encode_ber_object_identifier(oid_string)


def ber_length_group_values(content_len: int) -> List[bytes]:
    """Boofuzz ``Group`` values for a length-of-length field.

    The first entry is the correct definite-form length for ``content_len`` so
    the unmutated baseline renders a well-formed TLV (the fuzzer framework
    requires a spec-valid baseline); the remaining entries are the malformed
    long-form / indefinite mutations from ``BER_LENGTH_OF_LENGTH_MUTATIONS``
    that the campaign cycles through.

    Args:
        content_len: True length of the value bytes that follow this field

    Returns:
        List of raw length-field byte strings, valid form first
    """
    return [_encode_ber_length(content_len), *BER_LENGTH_OF_LENGTH_MUTATIONS]


def oid_content(oid_string: str) -> bytes:
    """Return the OID value bytes only (no OBJECT IDENTIFIER tag/length wrapper).

    ``encode_oid`` returns the full TLV (``06 <len> <body>``); length-of-length
    fuzzing needs the ``<body>`` alone so a malformed length octet can be spliced
    in front of it. The OIDs used here are all far shorter than 128 bytes, so the
    encoder always emits the single-octet definite length form and stripping the
    leading two bytes (tag + length) is exact.

    Args:
        oid_string: OID in dotted decimal notation

    Returns:
        BER-encoded OID content bytes (no tag, no length)
    """
    return encode_oid(oid_string)[2:]


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


__all__ = [
    "encode_oid",
    "oid_content",
    "ip_to_bytes",
    "hex_to_bytes",
    "BER_LENGTH_OF_LENGTH_MUTATIONS",
    "ber_length_group_values",
]
