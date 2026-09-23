"""
Custom OIDA fuzzer primitives

Provides Radamsa-powered alternatives to boofuzz's standard primitives.
"""

from oida.fuzz.primitives.radamsa_primitives import RadamsaString, RadamsaBytes, RadamsaBlock

from oida.fuzz.primitives.dynamic import (
    DynamicDWord,
    DynamicBytes,
    SmartString,
    SmartBytes,
    s_smart_string,
    s_smart_bytes,
)

from oida.fuzz.primitives.reduced_string import ReducedString, get_reduction_stats

from oida.fuzz.primitives.smart_string import SmartStringPrimitive, StringContext, smart_string

from oida.fuzz.primitives.tcp_data_offset import TCPDataOffsetByte

from oida.fuzz.primitives.asn1_blocks import (
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
