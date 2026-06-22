"""Regression tests for the boofuzz render() path of ASN.1 block primitives.

Guards against the bug where ASN1Primitive / ASN1Sequence overrode
Fuzzable.original_value as a @property returning bytes. boofuzz's
get_value() calls self.original_value(test_case_context=...), so a bytes
property made render()/get_value() raise
``TypeError: 'bytes' object is not callable``.
"""

from src.oida.fuzz.primitives.asn1_blocks import (
    ASN1Integer,
    ASN1OctetString,
    ASN1Sequence,
)


def test_asn1_integer_renders_via_boofuzz():
    prim = ASN1Integer("invoke_id", 42)
    # Before the fix both of these raised TypeError.
    assert prim.render() == b"\x02\x01\x2a"
    assert prim.get_value() == b"\x02\x01\x2a"


def test_asn1_integer_original_value_is_callable_method():
    prim = ASN1Integer("invoke_id", 42)
    # Must be a callable accepting boofuzz's test_case_context kwarg.
    assert prim.original_value() == b"\x02\x01\x2a"
    assert prim.original_value(test_case_context=None) == b"\x02\x01\x2a"


def test_asn1_sequence_renders_via_boofuzz():
    seq = ASN1Sequence(
        "request",
        children=[
            ASN1Integer("invoke_id", 1),
            ASN1OctetString("data", b"hi"),
        ],
    )
    rendered = seq.render()
    assert rendered == seq.get_value()
    # SEQUENCE tag 0x30, then child INTEGER (02 01 01) + OCTET STRING (04 02 6869).
    inner = b"\x02\x01\x01" + b"\x04\x02hi"
    assert rendered == b"\x30" + bytes([len(inner)]) + inner


def test_asn1_sequence_original_value_is_callable_method():
    seq = ASN1Sequence("request", children=[ASN1Integer("invoke_id", 1)])
    assert seq.original_value(test_case_context=None) == seq.render()
