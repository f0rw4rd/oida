"""Common SNMP encoding utilities shared across SNMPv1, v2c, and v3 fuzzers."""

from typing import List

from ..core.codecs.asn1 import ASN1Builder, ber_content
from ..primitives.asn1 import encode_ber_object_identifier
from ..primitives.asn1_blocks import encode_length as _encode_ber_length

# Shared ASN.1/BER builder driving the structured codec mutators (see
# structured_ber_varbind_values below).
_ASN1 = ASN1Builder()


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


def structured_ber_varbind_values(
    oid_string: str,
    value_tlv: bytes = b"\x05\x00",
    *,
    overflow_size: int = 200,
    nested_depth: int = 100,
    truncate_by: int = 1,
) -> List[bytes]:
    """Boofuzz ``Group`` values driving the structured ASN.1/BER codec mutators.

    Wires the previously call-site-less ``ASN1Builder`` structured mutators
    (``fuzz_tag_variants`` / ``build_truncated`` / ``build_with_overflow`` /
    ``build_nested_depth`` from ``oida.fuzz.core.codecs.asn1``) onto a single SNMP
    variable binding. These exercise parser attacks that the length-of-length /
    truncated-length nodes deliberately do NOT cover:

      * tag confusion  - the varbind SEQUENCE (0x30) tag swapped for wrong /
                         reserved / long-form tags (type-confusion decode paths)
      * length-lie     - a definite length that OVER-declares the content
                         (declared > actual; the SNMPvX_BER_Truncated_Length node
                         instead UNDER-declares), so the parser over-reads
      * overflow       - oversized varbind content (buffer-handling paths)
      * deep nesting   - repeated SEQUENCE wrapping for recursive-descent stack
                         exhaustion

    The first entry is a spec-valid varbind SEQUENCE so the unmutated baseline
    renders a well-formed PDU (the fuzzer framework requires a valid baseline).

    Args:
        oid_string: varbind OBJECT IDENTIFIER in dotted-decimal notation
        value_tlv: the varbind value TLV that follows the OID (default NULL 05 00)
        overflow_size: extra bytes appended by the overflow mutator
        nested_depth: SEQUENCE nesting depth for the stack-exhaustion mutator
        truncate_by: bytes withheld from the content by the length-lie mutator

    Returns:
        List of complete varbind TLV byte strings, spec-valid form first.
    """
    oid_tlv = encode_oid(oid_string)  # full OBJECT IDENTIFIER TLV (06 <len> <body>)
    valid_varbind = _ASN1.build_tlv(0x30, oid_tlv + value_tlv)
    # Length-aware strip of the SEQUENCE tag+length -> inner OID+value content.
    varbind_content = ber_content(valid_varbind)

    values: List[bytes] = [valid_varbind]
    # Tag confusion: keep the (valid) length+value, swap the leading 0x30 tag.
    values.extend(_ASN1.fuzz_tag_variants(0x30, valid_varbind[1:]))
    # Length-lie (over-declared): length says full size, content short by N.
    values.append(_ASN1.build_truncated(0x30, varbind_content, truncate_by=truncate_by))
    # Overflow: oversized content beyond the real OID+value.
    values.append(_ASN1.build_with_overflow(0x30, varbind_content, overflow_size=overflow_size))
    # Deep nesting: recursive-descent stack exhaustion.
    values.append(_ASN1.build_nested_depth(0x30, varbind_content, depth=nested_depth))
    return values


__all__ = [
    "encode_oid",
    "oid_content",
    "ip_to_bytes",
    "hex_to_bytes",
    "BER_LENGTH_OF_LENGTH_MUTATIONS",
    "ber_length_group_values",
    "structured_ber_varbind_values",
]
