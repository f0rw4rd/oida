"""
Custom OIDA fuzzer primitives

Provides Radamsa-powered alternatives to boofuzz's standard primitives.
"""

from .radamsa_primitives import (
    RadamsaString,
    RadamsaBytes,
    RadamsaBlock,
)

from .dynamic import (
    DynamicDWord,
    DynamicBytes,
    SmartString,
    SmartBytes,
    s_smart_string,
    s_smart_bytes,
)

from .reduced_string import (
    ReducedString,
    get_reduction_stats,
)

from .smart_string import (
    SmartStringPrimitive,
    StringContext,
    smart_string,
)

from .tcp_data_offset import (
    TCPDataOffsetByte,
)

from .delimited import (
    DelimitedField,
    DelimitedSegment,
    FramedMessage,
    HL7Delimiters,
    HL7Segment,
    HL7Message,
    build_delimiter_injection_values,
    build_oversized_field_values,
    build_mllp_corruption_values,
    build_encoding_char_values,
    build_segment_fuzzing_values,
)

from .asn1_blocks import (
    ASN1Tag,
    ASN1Primitive,
    ASN1Integer,
    ASN1Boolean,
    ASN1OctetString,
    ASN1BitString,
    ASN1OID,
    ASN1Null,
    ASN1VisibleString,
    ASN1Sequence,
)


__all__ = [
    "RadamsaString",
    "RadamsaBytes",
    "RadamsaBlock",
    "DynamicDWord",
    "DynamicBytes",
    "SmartString",
    "SmartBytes",
    "s_smart_string",
    "s_smart_bytes",
    "ReducedString",
    "get_reduction_stats",
    "SmartStringPrimitive",
    "StringContext",
    "smart_string",
    "TCPDataOffsetByte",
    # Delimited primitives
    "DelimitedField",
    "DelimitedSegment",
    "FramedMessage",
    "HL7Delimiters",
    "HL7Segment",
    "HL7Message",
    "build_delimiter_injection_values",
    "build_oversized_field_values",
    "build_mllp_corruption_values",
    "build_encoding_char_values",
    "build_segment_fuzzing_values",
    # ASN.1 primitives
    "ASN1Tag",
    "ASN1Primitive",
    "ASN1Integer",
    "ASN1Boolean",
    "ASN1OctetString",
    "ASN1BitString",
    "ASN1OID",
    "ASN1Null",
    "ASN1VisibleString",
    "ASN1Sequence",
]
