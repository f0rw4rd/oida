"""
Central ASN.1/BER encoding support for protocol fuzzers.

This module provides reusable ASN.1/BER encoding infrastructure used by
MMS-based protocols like TASE.2/ICCP and IEC 61850.

References:
- ITU-T X.690 (BER encoding rules)
- ISO 9506 (MMS)
- IEC 60870-6 (TASE.2)
"""

from typing import List, Union


def ber_content(tlv: bytes) -> bytes:
    """Return the content octets of a BER TLV (strip outer tag + length).

    Length-aware: a fixed ``tlv[2:]`` slice is only correct when the length
    is a single short-form octet (content < 128 bytes). For content >= 128
    bytes BER uses long-form length (``0x81 LL``, ``0x82 LL LL``, ...), so a
    fixed slice leaves stray length octets inside the content and silently
    emits a corrupt PDU. This reads the length octet and skips the right
    number of bytes.
    """
    if len(tlv) < 2:
        return b""
    length_octet = tlv[1]
    if length_octet < 0x80:
        return tlv[2:]  # short form: single length octet
    num_len_octets = length_octet & 0x7F
    return tlv[2 + num_len_octets :]  # long form: skip N length octets


class ASN1Tag:
    """ASN.1 tag constants."""

    # Tag classes (bits 7-6)
    CLASS_UNIVERSAL = 0x00
    CLASS_APPLICATION = 0x40
    CLASS_CONTEXT = 0x80
    CLASS_PRIVATE = 0xC0

    # Short aliases (kept for compatibility with callers that spell the tag
    # classes without the CLASS_ prefix, e.g. asn1_blocks.py's boofuzz
    # primitives).
    UNIVERSAL = CLASS_UNIVERSAL
    APPLICATION = CLASS_APPLICATION
    CONTEXT = CLASS_CONTEXT
    PRIVATE = CLASS_PRIVATE

    # Primitive/Constructed (bit 5)
    PRIMITIVE = 0x00
    CONSTRUCTED = 0x20

    # Universal tags (bits 4-0)
    BOOLEAN = 0x01
    INTEGER = 0x02
    BIT_STRING = 0x03
    OCTET_STRING = 0x04
    NULL = 0x05
    OBJECT_IDENTIFIER = 0x06
    OID = OBJECT_IDENTIFIER  # alias used by asn1_blocks.py's boofuzz primitives
    OBJECT_DESCRIPTOR = 0x07
    EXTERNAL = 0x08
    REAL = 0x09
    ENUMERATED = 0x0A
    EMBEDDED_PDV = 0x0B
    UTF8_STRING = 0x0C
    RELATIVE_OID = 0x0D
    SEQUENCE = 0x10 | CONSTRUCTED
    SET = 0x11 | CONSTRUCTED
    NUMERIC_STRING = 0x12
    PRINTABLE_STRING = 0x13
    TELETEX_STRING = 0x14
    VIDEOTEX_STRING = 0x15
    IA5_STRING = 0x16
    UTC_TIME = 0x17
    GENERALIZED_TIME = 0x18
    GRAPHIC_STRING = 0x19
    VISIBLE_STRING = 0x1A
    GENERAL_STRING = 0x1B
    UNIVERSAL_STRING = 0x1C
    CHARACTER_STRING = 0x1D
    BMP_STRING = 0x1E


def encode_length(length: int) -> bytes:
    """
    Encode a length value using BER length encoding.

    Args:
        length: The length value to encode

    Returns:
        BER-encoded length bytes
    """
    if length < 0:
        raise ValueError("Length cannot be negative")

    if length < 0x80:
        # Short form: single byte
        return bytes([length])
    elif length <= 0xFF:
        # Long form: 1 byte
        return bytes([0x81, length])
    elif length <= 0xFFFF:
        # Long form: 2 bytes
        return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])
    elif length <= 0xFFFFFF:
        # Long form: 3 bytes
        return bytes([0x83, (length >> 16) & 0xFF, (length >> 8) & 0xFF, length & 0xFF])
    else:
        # Long form: 4 bytes
        return bytes(
            [
                0x84,
                (length >> 24) & 0xFF,
                (length >> 16) & 0xFF,
                (length >> 8) & 0xFF,
                length & 0xFF,
            ]
        )


class ASN1Builder:
    """
    Central ASN.1/BER encoding support for protocol fuzzers.

    Provides methods for building ASN.1 encoded data with fuzzing capabilities.
    Supports both valid encoding and intentionally malformed data for security testing.
    """

    def __init__(self):
        """Initialize ASN1Builder."""
        self._fuzz_mode = False

    # =========================================================================
    # Core BER Encoding
    # =========================================================================

    def encode_length(self, length: int) -> bytes:
        """
        Encode a length value using BER length encoding.

        Args:
            length: The length value to encode

        Returns:
            BER-encoded length bytes
        """
        return encode_length(length)

    def encode_tag(self, tag_class: int, constructed: bool, tag_number: int) -> bytes:
        """
        Encode an ASN.1 tag.

        Args:
            tag_class: Tag class (UNIVERSAL, APPLICATION, CONTEXT, PRIVATE)
            constructed: True for constructed, False for primitive
            tag_number: Tag number

        Returns:
            BER-encoded tag bytes
        """
        first_byte = tag_class
        if constructed:
            first_byte |= ASN1Tag.CONSTRUCTED

        if tag_number < 0x1F:
            # Low tag number: fits in first byte
            return bytes([first_byte | tag_number])
        else:
            # High tag number: multi-byte encoding
            first_byte |= 0x1F
            result = [first_byte]

            # Encode tag number in base-128
            octets = []
            n = tag_number
            while n > 0:
                octets.append(n & 0x7F)
                n >>= 7

            # Add continuation bits
            for i in range(len(octets) - 1, 0, -1):
                result.append(octets[i] | 0x80)
            result.append(octets[0])

            return bytes(result)

    def build_tlv(self, tag: Union[int, bytes], value: bytes) -> bytes:
        """
        Build a TLV (Tag-Length-Value) structure.

        Args:
            tag: Tag byte(s) or single tag value
            value: Value bytes

        Returns:
            Complete TLV encoded bytes
        """
        if isinstance(tag, int):
            tag = bytes([tag])
        length = self.encode_length(len(value))
        return tag + length + value

    # =========================================================================
    # Primitive Type Builders
    # =========================================================================

    def build_boolean(self, value: bool) -> bytes:
        """Build a BOOLEAN primitive."""
        return self.build_tlv(ASN1Tag.BOOLEAN, bytes([0xFF if value else 0x00]))

    def build_integer(self, value: int, signed: bool = True) -> bytes:
        """
        Build an INTEGER primitive.

        Args:
            value: Integer value to encode
            signed: Whether to use signed encoding

        Returns:
            BER-encoded INTEGER
        """
        if value == 0:
            octets = bytes([0x00])
        elif value > 0:
            # Positive integer
            octets_list: list[int] = []
            n = value
            while n > 0:
                octets_list.insert(0, n & 0xFF)
                n >>= 8
            # Add leading zero if high bit set (to keep positive)
            if octets_list[0] & 0x80:
                octets_list.insert(0, 0x00)
            octets = bytes(octets_list)
        else:
            # Negative integer (two's complement)
            if not signed:
                raise ValueError("Cannot encode negative value as unsigned")

            # Find minimum number of bytes
            n = value
            neg_list: list[int] = []
            while True:
                neg_list.insert(0, n & 0xFF)
                n >>= 8
                if n == -1 and neg_list[0] & 0x80:
                    break
                if n == 0 and not (neg_list[0] & 0x80):
                    break
            octets = bytes(neg_list)

        return self.build_tlv(ASN1Tag.INTEGER, octets)

    def build_unsigned32(self, value: int) -> bytes:
        """Build an unsigned 32-bit INTEGER."""
        if value < 0 or value > 0xFFFFFFFF:
            raise ValueError("Value out of range for Unsigned32")

        octets = []
        if value == 0:
            octets = [0x00]
        else:
            n = value
            while n > 0:
                octets.insert(0, n & 0xFF)
                n >>= 8
            # Add leading zero if high bit set
            if octets[0] & 0x80:
                octets.insert(0, 0x00)

        return self.build_tlv(ASN1Tag.INTEGER, bytes(octets))

    def build_null(self) -> bytes:
        """Build a NULL primitive."""
        return bytes([ASN1Tag.NULL, 0x00])

    def build_octet_string(self, data: bytes) -> bytes:
        """Build an OCTET STRING primitive."""
        return self.build_tlv(ASN1Tag.OCTET_STRING, data)

    def build_bit_string(self, data: bytes, unused_bits: int = 0) -> bytes:
        """
        Build a BIT STRING primitive.

        Args:
            data: Bit string data
            unused_bits: Number of unused bits in the last byte (0-7)

        Returns:
            BER-encoded BIT STRING
        """
        if unused_bits < 0 or unused_bits > 7:
            raise ValueError("unused_bits must be 0-7")
        return self.build_tlv(ASN1Tag.BIT_STRING, bytes([unused_bits]) + data)

    def build_object_identifier(self, oid: Union[str, List[int]]) -> bytes:
        """
        Build an OBJECT IDENTIFIER primitive.

        Args:
            oid: OID as string (e.g., "1.2.840.113549") or list of integers

        Returns:
            BER-encoded OID
        """
        if isinstance(oid, str):
            components = [int(x) for x in oid.split(".")]
        else:
            components = list(oid)

        if len(components) < 2:
            raise ValueError("OID must have at least 2 components")

        def _base128(value: int) -> List[int]:
            """Encode a single arc value as base-128 octets (X.690 8.19.2)."""
            if value == 0:
                return [0]
            comp_octets = []
            n = value
            while n > 0:
                comp_octets.insert(0, n & 0x7F)
                n >>= 7
            # Set continuation bits on every octet but the last.
            for i in range(len(comp_octets) - 1):
                comp_octets[i] |= 0x80
            return comp_octets

        # First two components are combined into a single value (X.690
        # 8.19.4): 40 * arc1 + arc2. That combined value is itself just
        # another arc and must be base-128 encoded like the rest -- a raw
        # single byte overflows (e.g. arc1=2, arc2=999 -> 1079) whenever the
        # combined value exceeds 255.
        octets = _base128(40 * components[0] + components[1])

        # Remaining components in base-128
        for comp in components[2:]:
            octets.extend(_base128(comp))

        return self.build_tlv(ASN1Tag.OBJECT_IDENTIFIER, bytes(octets))

    def build_visible_string(self, text: str) -> bytes:
        """Build a VisibleString primitive."""
        return self.build_tlv(ASN1Tag.VISIBLE_STRING, text.encode("ascii"))

    def build_utf8_string(self, text: str) -> bytes:
        """Build a UTF8String primitive."""
        return self.build_tlv(ASN1Tag.UTF8_STRING, text.encode("utf-8"))

    # =========================================================================
    # Constructed Type Builders
    # =========================================================================

    def build_sequence(self, *items: bytes) -> bytes:
        """
        Build a SEQUENCE constructed type.

        Args:
            *items: BER-encoded items to include in sequence

        Returns:
            BER-encoded SEQUENCE
        """
        content = b"".join(items)
        return self.build_tlv(ASN1Tag.SEQUENCE, content)

    def build_context_specific(self, tag_num: int, value: bytes, constructed: bool = True) -> bytes:
        """
        Build an explicitly-tagged context-specific value.

        ``value`` is wrapped verbatim as the content of the context tag
        (explicit tagging), so the context tag is constructed -- the inner
        bytes are themselves a complete TLV. The ``constructed`` flag is kept
        for source compatibility but the tag is always constructed, matching
        the established MMS/ASN.1 encoding the callers depend on.

        Args:
            tag_num: Context-specific tag number
            value: Value bytes (a complete TLV)
            constructed: Retained for API compatibility (always constructed)

        Returns:
            Context-specific tagged bytes
        """
        tag = self.encode_tag(ASN1Tag.CLASS_CONTEXT, True, tag_num)
        return tag + self.encode_length(len(value)) + value

    # =========================================================================
    # Fuzzing Helpers
    # =========================================================================

    def fuzz_length_variants(self, content: bytes) -> List[bytes]:
        """
        Generate length field variants for fuzzing.

        Args:
            content: Original content

        Returns:
            List of bytes with various malformed length encodings
        """
        variants = []
        real_len = len(content)

        # Invalid length encodings
        variants.extend(
            [
                # Zero length with content
                bytes([0x00]) + content,
                # Truncated length
                bytes([real_len - 1 if real_len > 0 else 0]) + content,
                # Oversized length
                bytes([0x82, 0xFF, 0xFF]) + content,
                # Negative-looking length
                bytes([0x84, 0xFF, 0xFF, 0xFF, 0xFF]) + content,
                # Indefinite length (for fuzzing primitives that shouldn't have it)
                bytes([0x80]) + content + bytes([0x00, 0x00]),
                # Long form for short length
                bytes([0x81, real_len]) + content if real_len < 0x80 else b"",
                # Very long form
                bytes([0x84, 0x00, 0x00, 0x00, real_len]) + content if real_len < 0x100 else b"",
            ]
        )

        return [v for v in variants if v]  # Filter empty

    def fuzz_tag_variants(self, original_tag: int, content: bytes) -> List[bytes]:
        """
        Generate tag field variants for fuzzing.

        Args:
            original_tag: Original tag byte
            content: Original content with length

        Returns:
            List of bytes with various malformed tags
        """
        variants = []

        # Invalid universal tags
        for invalid_tag in [0x00, 0x0F, 0x1F, 0x3F, 0x5F, 0x7F, 0x9F, 0xBF, 0xDF, 0xFF]:
            variants.append(bytes([invalid_tag]) + content)

        # Long-form tag for short tag number
        variants.append(bytes([original_tag | 0x1F, original_tag & 0x1F]) + content)

        # Multi-byte tag with invalid continuation
        variants.append(bytes([0x1F, 0x80, 0x00]) + content)

        return variants

    def build_with_overflow(self, tag: int, content: bytes, overflow_size: int = 256) -> bytes:
        """
        Build a TLV with oversized content for buffer overflow testing.

        Args:
            tag: Tag byte
            content: Base content
            overflow_size: Number of overflow bytes to add

        Returns:
            TLV with overflow payload
        """
        overflow_content = content + (b"A" * overflow_size)
        # Use correct length to ensure content is processed
        return self.build_tlv(tag, overflow_content)

    def build_truncated(self, tag: int, content: bytes, truncate_by: int = 1) -> bytes:
        """
        Build a TLV with truncated content.

        Args:
            tag: Tag byte
            content: Original content
            truncate_by: Number of bytes to truncate

        Returns:
            TLV with length indicating more data than present
        """
        # Length says full size, but content is truncated
        full_len = len(content)
        truncated = content[:-truncate_by] if truncate_by < len(content) else b""

        tag_bytes = bytes([tag])

        return tag_bytes + self.encode_length(full_len) + truncated

    def build_nested_depth(self, tag: int, content: bytes, depth: int = 100) -> bytes:
        """
        Build deeply nested structures for stack exhaustion testing.

        Args:
            tag: Tag byte to use for nesting
            content: Innermost content
            depth: Nesting depth

        Returns:
            Deeply nested TLV structure
        """
        result = content
        for _ in range(depth):
            result = self.build_tlv(tag, result)
        return result

    # =========================================================================
    # MMS-Specific Helpers
    # =========================================================================


# Convenience singleton
asn1 = ASN1Builder()
