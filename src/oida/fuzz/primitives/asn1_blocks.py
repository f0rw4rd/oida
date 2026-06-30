"""
ASN.1 Boofuzz Primitives

Provides ASN.1-aware boofuzz blocks for fuzzing protocols using ASN.1/BER/DER encoding.
Supports MMS, LDAP, SNMP, X.509, and other ASN.1-based protocols.

These primitives understand ASN.1 TLV (Tag-Length-Value) structure and can:
- Generate valid ASN.1 encodings
- Mutate tags, lengths, and values independently
- Support nested structures (SEQUENCE, SET)
- Generate malformed ASN.1 for security testing

Usage:
    from oida.fuzz.primitives.asn1_blocks import (
        ASN1Integer, ASN1OctetString, ASN1Sequence, ASN1OID
    )

    # In protocol definition:
    ASN1Integer("invoke_id", 1)
    ASN1Sequence("request", children=[
        ASN1OID("service_oid", "1.0.9506.2.3"),
        ASN1OctetString("data", b"test"),
    ])
"""

from typing import List, Optional
from boofuzz import Fuzzable, Size

import logging

logger = logging.getLogger(__name__)


class ASN1Tag:
    """ASN.1 tag constants."""

    # Tag classes
    UNIVERSAL = 0x00
    APPLICATION = 0x40
    CONTEXT = 0x80
    PRIVATE = 0xC0

    # Primitive/Constructed
    PRIMITIVE = 0x00
    CONSTRUCTED = 0x20

    # Universal tags
    BOOLEAN = 0x01
    INTEGER = 0x02
    BIT_STRING = 0x03
    OCTET_STRING = 0x04
    NULL = 0x05
    OID = 0x06
    ENUMERATED = 0x0A
    UTF8_STRING = 0x0C
    SEQUENCE = 0x30
    SET = 0x31
    PRINTABLE_STRING = 0x13
    IA5_STRING = 0x16
    UTC_TIME = 0x17
    GENERALIZED_TIME = 0x18
    VISIBLE_STRING = 0x1A


def encode_length(length: int) -> bytes:
    """Encode ASN.1 BER length."""
    if length < 0x80:
        return bytes([length])
    elif length <= 0xFF:
        return bytes([0x81, length])
    elif length <= 0xFFFF:
        return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])
    elif length <= 0xFFFFFF:
        return bytes([0x83, (length >> 16) & 0xFF, (length >> 8) & 0xFF, length & 0xFF])
    else:
        return bytes(
            [
                0x84,
                (length >> 24) & 0xFF,
                (length >> 16) & 0xFF,
                (length >> 8) & 0xFF,
                length & 0xFF,
            ]
        )


class BERSize(Size):
    """ASN.1 BER-encoded length field for boofuzz.

    Drop-in replacement for boofuzz's Size primitive that outputs proper BER
    definite-form length encoding instead of raw fixed-width integers.

    Standard Size(length=1) outputs a single raw byte, which breaks BER for
    values >= 128 (0x80 is BER indefinite-length indicator). This class
    outputs correct BER: short form (1 byte) for 0-127, long form (2+ bytes)
    for >= 128.

    Usage:
        # Replace: Size("len", "block", length=1, output_format="binary", ...)
        # With:    BERSize("len", "block", ...)
        BERSize("Message_Length", "SNMP_Content", fuzzable=False)
    """

    def __init__(self, name: str, block_name: str, **kwargs):
        # Force settings that are correct for BER encoding
        kwargs.pop("length", None)
        kwargs.pop("endian", None)
        kwargs.pop("output_format", None)
        # Use length=4 as max capacity (BER long form up to 4 bytes)
        super().__init__(
            name=name,
            block_name=block_name,
            length=4,
            endian=">",
            output_format="binary",
            **kwargs,
        )

    def _length_to_bytes(self, length: int) -> bytes:
        """Override to produce BER definite-form length encoding."""
        return encode_length(self.math(length))


def encode_integer_content(value: int) -> bytes:
    """Encode integer value (without tag/length)."""
    if value == 0:
        return bytes([0x00])
    elif value > 0:
        octets = []
        n = value
        while n > 0:
            octets.insert(0, n & 0xFF)
            n >>= 8
        if octets[0] & 0x80:
            octets.insert(0, 0x00)
        return bytes(octets)
    else:
        # Negative (two's complement)
        octets = []
        n = value
        while True:
            octets.insert(0, n & 0xFF)
            n >>= 8
            if n == -1 and octets[0] & 0x80:
                break
            if n == 0 and not (octets[0] & 0x80):
                break
        return bytes(octets)


def encode_oid_content(oid_string: str) -> bytes:
    """Encode OID value (without tag/length)."""
    components = [int(x) for x in oid_string.split(".")]
    if len(components) < 2:
        raise ValueError("OID must have at least 2 components")

    encoded = bytearray([40 * components[0] + components[1]])

    for comp in components[2:]:
        if comp == 0:
            encoded.append(0)
        else:
            comp_octets = []
            n = comp
            while n > 0:
                comp_octets.insert(0, n & 0x7F)
                n >>= 7
            for i in range(len(comp_octets) - 1):
                comp_octets[i] |= 0x80
            encoded.extend(comp_octets)

    return bytes(encoded)


class ASN1Primitive(Fuzzable):
    """Base class for ASN.1 primitives with TLV fuzzing support."""

    def __init__(
        self,
        name: str,
        tag: int,
        default_value: bytes,
        fuzzable: bool = True,
        fuzz_tag: bool = True,
        fuzz_length: bool = True,
        fuzz_value: bool = True,
    ):
        """
        Initialize ASN.1 primitive.

        Args:
            name: Field name for identification
            tag: ASN.1 tag byte
            default_value: Default encoded value (content only, no tag/length)
            fuzzable: Enable fuzzing
            fuzz_tag: Include tag mutations
            fuzz_length: Include length mutations
            fuzz_value: Include value mutations
        """
        super().__init__(name=name, fuzzable=fuzzable)
        self._tag = tag
        self._default_value = default_value
        self._fuzz_tag = fuzz_tag
        self._fuzz_length = fuzz_length
        self._fuzz_value = fuzz_value
        self._mutations: List[bytes] = []
        self._generate_mutations()

    def _generate_mutations(self):
        """Generate all mutations for this primitive."""
        self._mutations = []

        # Valid encoding (always first)
        valid = self._encode_tlv(self._tag, self._default_value)
        self._mutations.append(valid)

        if not self._fuzzable:
            return

        # Tag mutations
        if self._fuzz_tag:
            self._mutations.extend(self._generate_tag_mutations())

        # Length mutations
        if self._fuzz_length:
            self._mutations.extend(self._generate_length_mutations())

        # Value mutations
        if self._fuzz_value:
            self._mutations.extend(self._generate_value_mutations())

    def _encode_tlv(self, tag: int, value: bytes) -> bytes:
        """Encode a complete TLV structure."""
        return bytes([tag]) + encode_length(len(value)) + value

    def _generate_tag_mutations(self) -> List[bytes]:
        """Generate tag field mutations."""
        mutations = []
        value = self._default_value
        length_bytes = encode_length(len(value))

        # Wrong universal tags
        for wrong_tag in [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x0A, 0x0C, 0x30, 0x31]:
            if wrong_tag != self._tag:
                mutations.append(bytes([wrong_tag]) + length_bytes + value)

        # Invalid tags
        for invalid_tag in [0x00, 0x1F, 0xFF, 0x80, 0xA0, 0xC0, 0xE0]:
            mutations.append(bytes([invalid_tag]) + length_bytes + value)

        # Constructed bit flip
        flipped = self._tag ^ 0x20
        mutations.append(bytes([flipped]) + length_bytes + value)

        # Long-form tag encoding
        mutations.append(bytes([self._tag | 0x1F, self._tag & 0x1F]) + length_bytes + value)

        return mutations

    def _generate_length_mutations(self) -> List[bytes]:
        """Generate length field mutations."""
        mutations = []
        tag_byte = bytes([self._tag])
        value = self._default_value
        real_len = len(value)

        # Zero length with content
        mutations.append(tag_byte + bytes([0x00]) + value)

        # Truncated length (shorter than content)
        if real_len > 1:
            mutations.append(tag_byte + bytes([real_len - 1]) + value)

        # Oversized length
        mutations.append(tag_byte + bytes([0x82, 0xFF, 0xFF]) + value)

        # Negative-looking length
        mutations.append(tag_byte + bytes([0x84, 0xFF, 0xFF, 0xFF, 0xFF]) + value)

        # Indefinite length (for primitives - invalid)
        mutations.append(tag_byte + bytes([0x80]) + value + bytes([0x00, 0x00]))

        # Long form for short length
        if real_len < 0x80:
            mutations.append(tag_byte + bytes([0x81, real_len]) + value)

        # Very long form
        if real_len < 0x100:
            mutations.append(tag_byte + bytes([0x84, 0x00, 0x00, 0x00, real_len]) + value)

        return mutations

    def _generate_value_mutations(self) -> List[bytes]:
        """Generate value mutations - override in subclasses."""
        return []

    def mutations(self, default_value):
        """Return mutation iterator."""
        for mutation in self._mutations[1:]:  # Skip first (valid) encoding
            yield mutation

    def num_mutations(self, default_value=None):
        """Return number of mutations."""
        return len(self._mutations) - 1  # Exclude valid encoding

    def encode(self, value, mutation_context):
        """Encode the current value."""
        if mutation_context and mutation_context.mutation_index < len(self._mutations):
            return self._mutations[mutation_context.mutation_index]
        return self._mutations[0]  # Valid encoding

    def original_value(self, test_case_context=None):
        """Return the original (valid) encoded value.

        Matches boofuzz's Fuzzable.original_value contract: it is a method
        (callable with an optional test_case_context), not a property.
        """
        return self._mutations[0] if self._mutations else b""


class ASN1Integer(ASN1Primitive):
    """ASN.1 INTEGER primitive with fuzzing support."""

    def __init__(
        self,
        name: str,
        default_value: int = 0,
        fuzzable: bool = True,
        fuzz_tag: bool = True,
        fuzz_length: bool = True,
        fuzz_value: bool = True,
        context_tag: Optional[int] = None,
    ):
        """
        Create an ASN.1 INTEGER.

        Args:
            name: Field name
            default_value: Default integer value
            fuzzable: Enable fuzzing
            fuzz_tag: Include tag mutations
            fuzz_length: Include length mutations
            fuzz_value: Include value mutations
            context_tag: Optional context-specific tag number
        """
        self._int_value = default_value

        if context_tag is not None:
            tag = ASN1Tag.CONTEXT | context_tag
        else:
            tag = ASN1Tag.INTEGER

        content = encode_integer_content(default_value)
        super().__init__(name, tag, content, fuzzable, fuzz_tag, fuzz_length, fuzz_value)

    def _generate_value_mutations(self) -> List[bytes]:
        """Generate integer-specific value mutations."""
        mutations = []
        tag_byte = bytes([self._tag])

        # Boundary values
        boundary_values = [
            0,
            1,
            -1,
            127,
            128,
            255,
            256,
            32767,
            32768,
            65535,
            65536,
            2147483647,
            2147483648,
            4294967295,
            -128,
            -129,
            -32768,
            -32769,
            -2147483648,
            -2147483649,
        ]

        for val in boundary_values:
            if val != self._int_value:
                try:
                    content = encode_integer_content(val)
                    mutations.append(tag_byte + encode_length(len(content)) + content)
                except (OverflowError, ValueError) as e:
                    logger.debug(f"Failed to get content: {e}")

        # Empty content
        mutations.append(tag_byte + bytes([0x00]))

        # Oversized integer (padding)
        content = bytes([0x00] * 10) + encode_integer_content(self._int_value)
        mutations.append(tag_byte + encode_length(len(content)) + content)

        return mutations


class ASN1Boolean(ASN1Primitive):
    """ASN.1 BOOLEAN primitive with fuzzing support."""

    def __init__(
        self,
        name: str,
        default_value: bool = False,
        fuzzable: bool = True,
        context_tag: Optional[int] = None,
    ):
        self._bool_value = default_value

        if context_tag is not None:
            tag = ASN1Tag.CONTEXT | context_tag
        else:
            tag = ASN1Tag.BOOLEAN

        content = bytes([0xFF if default_value else 0x00])
        super().__init__(name, tag, content, fuzzable)

    def _generate_value_mutations(self) -> List[bytes]:
        """Generate boolean-specific mutations."""
        mutations = []
        tag_byte = bytes([self._tag])

        # Opposite value
        opposite = bytes([0x00 if self._bool_value else 0xFF])
        mutations.append(tag_byte + bytes([0x01]) + opposite)

        # Invalid boolean values
        for invalid in [0x01, 0x7F, 0x80, 0xFE]:
            mutations.append(tag_byte + bytes([0x01, invalid]))

        # Multi-byte boolean (invalid)
        mutations.append(tag_byte + bytes([0x02, 0xFF, 0xFF]))

        # Empty boolean
        mutations.append(tag_byte + bytes([0x00]))

        return mutations


class ASN1OctetString(ASN1Primitive):
    """ASN.1 OCTET STRING primitive with fuzzing support."""

    def __init__(
        self,
        name: str,
        default_value: bytes = b"",
        fuzzable: bool = True,
        max_len: int = 1024,
        context_tag: Optional[int] = None,
    ):
        self._max_len = max_len

        if context_tag is not None:
            tag = ASN1Tag.CONTEXT | context_tag
        else:
            tag = ASN1Tag.OCTET_STRING

        super().__init__(name, tag, default_value, fuzzable)

    def _generate_value_mutations(self) -> List[bytes]:
        """Generate octet string mutations."""
        mutations = []
        tag_byte = bytes([self._tag])

        # Empty string
        mutations.append(tag_byte + bytes([0x00]))

        # Single byte
        mutations.append(tag_byte + bytes([0x01, 0x00]))
        mutations.append(tag_byte + bytes([0x01, 0xFF]))

        # Long strings
        for length in [256, 1024, 4096]:
            if length <= self._max_len:
                content = b"A" * length
                mutations.append(tag_byte + encode_length(len(content)) + content)

        # Binary patterns
        patterns = [
            b"\x00" * 16,
            b"\xff" * 16,
            b"\x00\xff" * 8,
            bytes(range(256)),
        ]
        for pattern in patterns:
            mutations.append(tag_byte + encode_length(len(pattern)) + pattern)

        return mutations


class ASN1BitString(ASN1Primitive):
    """ASN.1 BIT STRING primitive with fuzzing support."""

    def __init__(
        self,
        name: str,
        default_value: bytes = b"",
        unused_bits: int = 0,
        fuzzable: bool = True,
        context_tag: Optional[int] = None,
    ):
        self._bits_value = default_value

        if context_tag is not None:
            tag = ASN1Tag.CONTEXT | context_tag
        else:
            tag = ASN1Tag.BIT_STRING

        content = bytes([unused_bits]) + default_value
        super().__init__(name, tag, content, fuzzable)

    def _generate_value_mutations(self) -> List[bytes]:
        """Generate bit string mutations."""
        mutations = []
        tag_byte = bytes([self._tag])

        # Invalid unused bits values
        for unused in [8, 9, 255]:
            content = bytes([unused]) + self._bits_value
            mutations.append(tag_byte + encode_length(len(content)) + content)

        # Empty bit string (just unused bits)
        mutations.append(tag_byte + bytes([0x01, 0x00]))

        # All ones/zeros
        mutations.append(tag_byte + bytes([0x02, 0x00, 0xFF]))
        mutations.append(tag_byte + bytes([0x02, 0x00, 0x00]))

        return mutations


class ASN1OID(ASN1Primitive):
    """ASN.1 OBJECT IDENTIFIER primitive with fuzzing support."""

    def __init__(
        self,
        name: str,
        default_value: str = "1.2.3",
        fuzzable: bool = True,
        context_tag: Optional[int] = None,
    ):
        self._oid_string = default_value

        if context_tag is not None:
            tag = ASN1Tag.CONTEXT | context_tag
        else:
            tag = ASN1Tag.OID

        content = encode_oid_content(default_value)
        super().__init__(name, tag, content, fuzzable)

    def _generate_value_mutations(self) -> List[bytes]:
        """Generate OID mutations."""
        mutations = []
        tag_byte = bytes([self._tag])

        # Common OIDs
        common_oids = [
            "1.2.840.113549.1.1.1",  # RSA
            "1.2.840.10045.4.3.2",  # ECDSA
            "1.3.6.1.4.1",  # Enterprises
            "2.5.4.3",  # CN
            "1.0.9506.2.3",  # MMS
        ]
        for oid in common_oids:
            if oid != self._oid_string:
                try:
                    content = encode_oid_content(oid)
                    mutations.append(tag_byte + encode_length(len(content)) + content)
                except ValueError as e:
                    logger.debug(f"Failed to get content: {e}")

        # Empty OID
        mutations.append(tag_byte + bytes([0x00]))

        # Single byte OID
        mutations.append(tag_byte + bytes([0x01, 0x00]))

        # Very long OID components
        long_oid = bytes([0x28, 0x83, 0xFF, 0xFF, 0x7F])  # Large component
        mutations.append(tag_byte + encode_length(len(long_oid)) + long_oid)

        return mutations


class ASN1Null(ASN1Primitive):
    """ASN.1 NULL primitive."""

    def __init__(self, name: str, fuzzable: bool = True, context_tag: Optional[int] = None):
        if context_tag is not None:
            tag = ASN1Tag.CONTEXT | context_tag
        else:
            tag = ASN1Tag.NULL

        super().__init__(name, tag, b"", fuzzable, fuzz_value=False)

    def _generate_length_mutations(self) -> List[bytes]:
        """Generate NULL-specific length mutations."""
        mutations = super()._generate_length_mutations()
        tag_byte = bytes([self._tag])

        # NULL with content (invalid)
        mutations.append(tag_byte + bytes([0x01, 0x00]))
        mutations.append(tag_byte + bytes([0x02, 0x00, 0x00]))

        return mutations


class ASN1VisibleString(ASN1Primitive):
    """ASN.1 VisibleString primitive with fuzzing support."""

    def __init__(
        self,
        name: str,
        default_value: str = "",
        fuzzable: bool = True,
        max_len: int = 256,
        context_tag: Optional[int] = None,
    ):
        self._max_len = max_len

        if context_tag is not None:
            tag = ASN1Tag.CONTEXT | context_tag
        else:
            tag = ASN1Tag.VISIBLE_STRING

        content = default_value.encode("ascii", errors="replace")
        super().__init__(name, tag, content, fuzzable)

    def _generate_value_mutations(self) -> List[bytes]:
        """Generate string mutations."""
        mutations = []
        tag_byte = bytes([self._tag])

        # Empty string
        mutations.append(tag_byte + bytes([0x00]))

        # Long strings
        for pattern in ["A", "%n", "\x00"]:
            for length in [128, 256, 1024]:
                if length <= self._max_len:
                    content = (pattern * length)[:length].encode("ascii", errors="replace")
                    mutations.append(tag_byte + encode_length(len(content)) + content)

        # Format strings
        format_strings = ["%s%s%s%s", "%x%x%x%x", "%n%n%n%n", "${jndi:ldap://x}"]
        for fmt in format_strings:
            content = fmt.encode("ascii", errors="replace")
            mutations.append(tag_byte + encode_length(len(content)) + content)

        # Non-ASCII (invalid for VisibleString)
        mutations.append(tag_byte + bytes([0x04, 0x80, 0x81, 0xFF, 0xFE]))

        return mutations


class ASN1Sequence(Fuzzable):
    """ASN.1 SEQUENCE container with nested element fuzzing."""

    def __init__(
        self,
        name: str,
        children: Optional[List[ASN1Primitive]] = None,
        fuzzable: bool = True,
        fuzz_tag: bool = True,
        fuzz_length: bool = True,
        context_tag: Optional[int] = None,
    ):
        """
        Create an ASN.1 SEQUENCE.

        Args:
            name: Field name
            children: List of ASN1Primitive children
            fuzzable: Enable fuzzing
            fuzz_tag: Include tag mutations
            fuzz_length: Include length mutations
            context_tag: Optional context-specific tag number
        """
        super().__init__(name=name, fuzzable=fuzzable)
        self._children = children or []
        self._fuzz_tag = fuzz_tag
        self._fuzz_length = fuzz_length

        if context_tag is not None:
            self._tag = ASN1Tag.CONTEXT | ASN1Tag.CONSTRUCTED | context_tag
        else:
            self._tag = ASN1Tag.SEQUENCE

        self._mutations: List[bytes] = []
        self._generate_mutations()

    def _get_children_content(self) -> bytes:
        """Get concatenated children content."""
        content = b""
        for child in self._children:
            content += child.original_value()
        return content

    def _encode_sequence(self, content: bytes) -> bytes:
        """Encode complete SEQUENCE."""
        return bytes([self._tag]) + encode_length(len(content)) + content

    def _generate_mutations(self):
        """Generate SEQUENCE mutations."""
        self._mutations = []

        # Valid encoding
        content = self._get_children_content()
        self._mutations.append(self._encode_sequence(content))

        if not self._fuzzable:
            return

        # Tag mutations
        if self._fuzz_tag:
            for wrong_tag in [0x30, 0x31, 0xA0, 0xA1, 0x04, 0x02]:
                if wrong_tag != self._tag:
                    self._mutations.append(
                        bytes([wrong_tag]) + encode_length(len(content)) + content
                    )

        # Length mutations
        if self._fuzz_length:
            tag_byte = bytes([self._tag])
            real_len = len(content)

            # Zero length
            self._mutations.append(tag_byte + bytes([0x00]) + content)

            # Truncated
            if real_len > 1:
                self._mutations.append(tag_byte + bytes([real_len - 1]) + content)

            # Oversized
            self._mutations.append(tag_byte + bytes([0x82, 0xFF, 0xFF]) + content)

            # Indefinite length (valid for constructed)
            self._mutations.append(tag_byte + bytes([0x80]) + content + bytes([0x00, 0x00]))

        # Empty sequence
        self._mutations.append(bytes([self._tag, 0x00]))

        # Missing children (one at a time)
        for i in range(len(self._children)):
            partial = b""
            for j, child in enumerate(self._children):
                if j != i:
                    partial += child.original_value()
            self._mutations.append(self._encode_sequence(partial))

        # Duplicated children
        if self._children:
            doubled = content + self._children[0].original_value()
            self._mutations.append(self._encode_sequence(doubled))

        # Deeply nested (stack exhaustion)
        nested = content
        for _ in range(50):
            nested = bytes([0x30]) + encode_length(len(nested)) + nested
        self._mutations.append(nested)

    def mutations(self, default_value):
        for mutation in self._mutations[1:]:
            yield mutation

    def num_mutations(self, default_value=None):
        return len(self._mutations) - 1

    def encode(self, value, mutation_context):
        if mutation_context and mutation_context.mutation_index < len(self._mutations):
            return self._mutations[mutation_context.mutation_index]
        return self._mutations[0]

    def original_value(self, test_case_context=None):
        """Return the original (valid) encoded value.

        Method (not a property) to match boofuzz's Fuzzable.original_value
        contract, which get_value() calls with test_case_context.
        """
        return self._mutations[0] if self._mutations else b""


# Export all
__all__ = [
    # Constants
    "ASN1Tag",
    # BER-aware Size
    "BERSize",
    # Primitives
    "ASN1Primitive",
    "ASN1Integer",
    "ASN1Boolean",
    "ASN1OctetString",
    "ASN1BitString",
    "ASN1OID",
    "ASN1Null",
    "ASN1VisibleString",
    "ASN1Sequence",
    # Helper functions
    "encode_length",
    "encode_integer_content",
    "encode_oid_content",
]
