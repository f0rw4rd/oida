"""
ASN.1 Primitives for Protocol Fuzzing

Provides ASN.1 BER (Basic Encoding Rules) encoding primitives for MMS, GOOSE,
and other protocols requiring ASN.1 encoding.

This module provides backward-compatible function wrappers around the central
ASN1Builder class in core/codecs/asn1.py.

Based on ITU-T X.690 standard.
"""

from typing import Union, Optional

# Import the canonical ASN.1 implementation
from oida.fuzz.core.codecs.asn1 import ASN1Builder, ASN1Tag

# Singleton builder instance for module-level functions
_builder = ASN1Builder()


def encode_ber_length(length: int) -> bytes:
    """
    Encode length field using ASN.1 BER definite form.

    Args:
        length: Length value to encode

    Returns:
        Encoded length bytes

    Examples:
        >>> encode_ber_length(5).hex()
        '05'
        >>> encode_ber_length(200).hex()
        '81c8'
        >>> encode_ber_length(1000).hex()
        '8203e8'
    """
    return _builder.encode_length(length)


def encode_ber_integer(value: int, tag_value: int = 0x02) -> bytes:
    """
    Encode integer using ASN.1 BER.

    Args:
        value: Integer value to encode
        tag_value: ASN.1 tag (default 0x02 for universal INTEGER)

    Returns:
        Complete ASN.1 INTEGER encoding

    Examples:
        >>> encode_ber_integer(42).hex()
        '02012a'
        >>> encode_ber_integer(1000).hex()
        '020203e8'
    """
    if tag_value == ASN1Tag.INTEGER:
        return _builder.build_integer(value)
    # Custom tag - build manually
    integer_bytes = _builder.build_integer(value)
    return bytes([tag_value]) + integer_bytes[1:]  # Replace tag


def encode_ber_boolean(value: bool, tag_value: int = 0x01) -> bytes:
    """
    Encode boolean using ASN.1 BER.

    Args:
        value: Boolean value
        tag_value: ASN.1 tag (default 0x01 for universal BOOLEAN)

    Returns:
        Complete ASN.1 BOOLEAN encoding
    """
    if tag_value == ASN1Tag.BOOLEAN:
        return _builder.build_boolean(value)
    content = bytes([0xFF if value else 0x00])
    return bytes([tag_value, 0x01]) + content


def encode_ber_octet_string(data: bytes, tag_value: int = 0x04) -> bytes:
    """
    Encode octet string using ASN.1 BER.

    Args:
        data: Byte data to encode
        tag_value: ASN.1 tag (default 0x04 for universal OCTET STRING)

    Returns:
        Complete ASN.1 OCTET STRING encoding
    """
    if tag_value == ASN1Tag.OCTET_STRING:
        return _builder.build_octet_string(data)
    return bytes([tag_value]) + _builder.encode_length(len(data)) + data


def encode_ber_visible_string(text: str, tag_value: int = 0x1A) -> bytes:
    """
    Encode visible string using ASN.1 BER.

    Args:
        text: String to encode (ASCII)
        tag_value: ASN.1 tag (default 0x1A for universal VisibleString)

    Returns:
        Complete ASN.1 VisibleString encoding
    """
    if tag_value == ASN1Tag.VISIBLE_STRING:
        return _builder.build_visible_string(text)
    data = text.encode("ascii")
    return bytes([tag_value]) + _builder.encode_length(len(data)) + data


def encode_ber_utf8_string(text: str, tag_value: int = 0x0C) -> bytes:
    """
    Encode UTF-8 string using ASN.1 BER.

    Args:
        text: String to encode (UTF-8)
        tag_value: ASN.1 tag (default 0x0C for universal UTF8String)

    Returns:
        Complete ASN.1 UTF8String encoding
    """
    if tag_value == ASN1Tag.UTF8_STRING:
        return _builder.build_utf8_string(text)
    data = text.encode("utf-8")
    return bytes([tag_value]) + _builder.encode_length(len(data)) + data


def encode_ber_object_identifier(oid_string: str, tag_value: int = 0x06) -> bytes:
    """
    Encode Object Identifier using ASN.1 BER.

    Args:
        oid_string: OID in dotted notation (e.g., "1.0.9506.2.3")
        tag_value: ASN.1 tag (default 0x06 for universal OBJECT IDENTIFIER)

    Returns:
        Complete ASN.1 OBJECT IDENTIFIER encoding

    Examples:
        >>> encode_ber_object_identifier("1.0.9506.2.3").hex()
        '060528ca220203'
    """
    if tag_value == ASN1Tag.OBJECT_IDENTIFIER:
        return _builder.build_object_identifier(oid_string)
    # Custom tag - rebuild with different tag
    oid_bytes = _builder.build_object_identifier(oid_string)
    return bytes([tag_value]) + oid_bytes[1:]


def encode_ber_sequence(contents: bytes, tag_value: int = 0x30) -> bytes:
    """
    Encode SEQUENCE using ASN.1 BER.

    Args:
        contents: Pre-encoded contents of the sequence
        tag_value: ASN.1 tag (default 0x30 for universal SEQUENCE)

    Returns:
        Complete ASN.1 SEQUENCE encoding
    """
    return bytes([tag_value]) + _builder.encode_length(len(contents)) + contents


def encode_ber_set(contents: bytes, tag_value: int = 0x31) -> bytes:
    """
    Encode SET using ASN.1 BER.

    Args:
        contents: Pre-encoded contents of the set
        tag_value: ASN.1 tag (default 0x31 for universal SET)

    Returns:
        Complete ASN.1 SET encoding
    """
    return bytes([tag_value]) + _builder.encode_length(len(contents)) + contents


def encode_ber_context_tag(tag_number: int, contents: bytes, constructed: bool = False) -> bytes:
    """
    Encode context-specific tag using ASN.1 BER.

    Args:
        tag_number: Context tag number (0-30 for simple form)
        contents: Pre-encoded contents
        constructed: True if contents are constructed (SEQUENCE/SET), False for primitive

    Returns:
        Complete context-tagged encoding

    Examples:
        >>> encode_ber_context_tag(0, b'\\x01', False).hex()
        '800101'
        >>> encode_ber_context_tag(1, encode_ber_integer(42), True).hex()
        'a10302012a'
    """
    if tag_number > 30:
        raise ValueError("Tag numbers > 30 require long form (not yet implemented)")
    # Context class (0b10), constructed/primitive bit, tag number
    tag_byte = 0x80 | (0x20 if constructed else 0x00) | tag_number
    return bytes([tag_byte]) + _builder.encode_length(len(contents)) + contents


def encode_ber_application_tag(
    tag_number: int, contents: bytes, constructed: bool = False
) -> bytes:
    """
    Encode application-specific tag using ASN.1 BER.

    Args:
        tag_number: Application tag number
        contents: Pre-encoded contents
        constructed: True if contents are constructed

    Returns:
        Complete application-tagged encoding
    """
    if tag_number > 30:
        raise ValueError("Tag numbers > 30 require long form (not yet implemented)")
    # Application class (0b01), constructed/primitive bit, tag number
    tag_byte = 0x40 | (0x20 if constructed else 0x00) | tag_number
    return bytes([tag_byte]) + _builder.encode_length(len(contents)) + contents


def encode_ber_bitstring(
    bits: Union[bytes, str], unused_bits: int = 0, tag_value: int = 0x03
) -> bytes:
    """
    Encode BIT STRING using ASN.1 BER.

    Args:
        bits: Bit values as bytes or binary string (e.g., "10110010")
        unused_bits: Number of unused bits in last byte (0-7)
        tag_value: ASN.1 tag (default 0x03 for universal BIT STRING)

    Returns:
        Complete ASN.1 BIT STRING encoding
    """
    if isinstance(bits, str):
        # Convert binary string to bytes
        bit_length = len(bits)
        byte_length = (bit_length + 7) // 8
        unused_bits = (byte_length * 8) - bit_length

        bit_bytes = bytearray()
        for i in range(0, bit_length, 8):
            byte_str = bits[i : i + 8].ljust(8, "0")
            bit_bytes.append(int(byte_str, 2))
        bits = bytes(bit_bytes)

    if tag_value == ASN1Tag.BIT_STRING:
        return _builder.build_bit_string(bits, unused_bits)
    content = bytes([unused_bits]) + bits
    return bytes([tag_value]) + _builder.encode_length(len(content)) + content


# MMS-specific convenience functions


def encode_mms_oid() -> bytes:
    """
    Encode MMS OID (1.0.9506.2.3).

    This is the standard MMS ASO-context-name OID.

    Returns:
        Encoded MMS OID: 0x28 0xca 0x22 0x02 0x03
    """
    return encode_ber_object_identifier("1.0.9506.2.3")


def encode_mms_integer(value: int, context_tag: Optional[int] = None) -> bytes:
    """
    Encode MMS integer (optionally with context tag).

    Args:
        value: Integer value
        context_tag: Optional context tag number

    Returns:
        Encoded integer
    """
    integer_bytes = _builder.build_integer(value)
    if context_tag is not None:
        return _builder.build_context_specific(context_tag, integer_bytes, constructed=False)
    return integer_bytes


def encode_mms_visible_string(text: str, context_tag: Optional[int] = None) -> bytes:
    """
    Encode MMS visible string (optionally with context tag).

    Args:
        text: String value
        context_tag: Optional context tag number

    Returns:
        Encoded string
    """
    string_bytes = _builder.build_visible_string(text)
    if context_tag is not None:
        return _builder.build_context_specific(context_tag, string_bytes, constructed=False)
    return string_bytes


def encode_mms_boolean(value: bool, context_tag: Optional[int] = None) -> bytes:
    """
    Encode MMS boolean (optionally with context tag).

    Args:
        value: Boolean value
        context_tag: Optional context tag number

    Returns:
        Encoded boolean
    """
    boolean_bytes = _builder.build_boolean(value)
    if context_tag is not None:
        return _builder.build_context_specific(context_tag, boolean_bytes, constructed=False)
    return boolean_bytes


# =============================================================================
# Valid ASN.1 Types (pyasn1) - NOT MUTATED
# =============================================================================
# These are re-exports from pyasn1 for building valid, spec-compliant packets.
# Use these for:
#   - Protocol handshakes that must be valid
#   - Response parsing/decoding
#   - Building baseline packets before fuzzing
#
# For FUZZING (mutated packets), use the ASN1* classes from asn1_blocks.py:
#   from oida.fuzz.primitives import ASN1Integer, ASN1Sequence  # FUZZED
#
# For VALID packets, use these:
#   from oida.fuzz.primitives.asn1 import ValidInteger, ValidSequence  # NOT FUZZED

from pyasn1.type import univ as _univ
from pyasn1.type import char as _char
from pyasn1.type import useful as _useful
from pyasn1.type import tag as _tag
from pyasn1.type import constraint as _constraint
from pyasn1.codec.ber import encoder as _ber_encoder
from pyasn1.codec.ber import decoder as _ber_decoder
from pyasn1.codec.der import encoder as _der_encoder
from pyasn1.codec.der import decoder as _der_decoder

# Valid (non-mutated) ASN.1 types - prefix makes intent clear
ValidInteger = _univ.Integer
ValidBoolean = _univ.Boolean
ValidOctetString = _univ.OctetString
ValidBitString = _univ.BitString
ValidNull = _univ.Null
ValidOID = _univ.ObjectIdentifier
ValidSequence = _univ.Sequence
ValidSet = _univ.Set
ValidChoice = _univ.Choice
ValidAny = _univ.Any
ValidReal = _univ.Real
ValidEnumerated = _univ.Enumerated
ValidUTF8String = _char.UTF8String
ValidIA5String = _char.IA5String
ValidPrintableString = _char.PrintableString
ValidVisibleString = _char.VisibleString
ValidGeneralizedTime = _useful.GeneralizedTime
ValidUTCTime = _useful.UTCTime

# Tagging helpers
ValidTag = _tag.Tag
ValidTagSet = _tag.TagSet

# Constraints
ValidConstraint = _constraint.ConstraintsIntersection
ValidValueRange = _constraint.ValueRangeConstraint
ValidValueSize = _constraint.ValueSizeConstraint


def valid_encode(asn1_obj, encoding: str = "ber") -> bytes:
    """
    Encode an ASN.1 object to bytes (valid, NOT mutated).

    Args:
        asn1_obj: pyasn1 object to encode
        encoding: 'ber' or 'der'

    Returns:
        Encoded bytes

    Example:
        >>> seq = ValidSequence()
        >>> seq.setComponentByPosition(0, ValidInteger(42))
        >>> valid_encode(seq)
        b'0\\x03\\x02\\x01*'
    """
    if encoding == "der":
        return _der_encoder.encode(asn1_obj)
    return _ber_encoder.encode(asn1_obj)


def valid_decode(data: bytes, asn1_spec=None, encoding: str = "ber"):
    """
    Decode bytes to an ASN.1 object (for parsing responses).

    Args:
        data: Bytes to decode
        asn1_spec: Optional ASN.1 type specification
        encoding: 'ber' or 'der'

    Returns:
        Tuple of (decoded_object, remainder_bytes)

    Example:
        >>> obj, remainder = valid_decode(b'\\x02\\x01\\x2a')
        >>> int(obj)
        42
    """
    if encoding == "der":
        return _der_decoder.decode(data, asn1Spec=asn1_spec)
    return _ber_decoder.decode(data, asn1Spec=asn1_spec)


# Re-export ASN1Builder and ASN1Tag for direct access
__all__ = [
    # Core classes
    "ASN1Builder",
    "ASN1Tag",
    # BER encoding functions
    "encode_ber_length",
    "encode_ber_integer",
    "encode_ber_boolean",
    "encode_ber_octet_string",
    "encode_ber_visible_string",
    "encode_ber_utf8_string",
    "encode_ber_object_identifier",
    "encode_ber_sequence",
    "encode_ber_set",
    "encode_ber_context_tag",
    "encode_ber_application_tag",
    "encode_ber_bitstring",
    # MMS-specific
    "encode_mms_oid",
    "encode_mms_integer",
    "encode_mms_visible_string",
    "encode_mms_boolean",
    # Valid (non-mutated) ASN.1 types from pyasn1
    "ValidInteger",
    "ValidBoolean",
    "ValidOctetString",
    "ValidBitString",
    "ValidNull",
    "ValidOID",
    "ValidSequence",
    "ValidSet",
    "ValidChoice",
    "ValidAny",
    "ValidReal",
    "ValidEnumerated",
    "ValidUTF8String",
    "ValidIA5String",
    "ValidPrintableString",
    "ValidVisibleString",
    "ValidGeneralizedTime",
    "ValidUTCTime",
    "ValidTag",
    "ValidTagSet",
    "ValidConstraint",
    "ValidValueRange",
    "ValidValueSize",
    "valid_encode",
    "valid_decode",
]
