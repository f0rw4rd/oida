"""Regression tests for the MMS/ASN.1 codec BER-length correctness.

The codec used to strip a BER TLV's tag+length with a fixed ``[2:]`` slice,
which is only correct for short-form lengths (content < 128 bytes). For
content >= 128 bytes BER switches to long-form length (``0x81 LL`` ...), so
the fixed slice left stray length octets inside the content and silently
emitted a corrupt PDU. ``ber_content()`` is length-aware; these tests pin
that behaviour so the bug can't regress.
"""

import pytest

from oida.fuzz.core.codecs.asn1 import ASN1Builder, ber_content
from oida.fuzz.core.codecs.mms import MMSCodec

pytestmark = pytest.mark.core


def test_ber_content_short_form():
    """Short-form length (content < 128B): content extracted exactly."""
    tlv = ASN1Builder().build_octet_string(b"hi")
    assert ber_content(tlv) == b"hi"


def test_ber_content_long_form_extracts_exact_content():
    """Long-form length (content >= 128B): no stray length octets leak in."""
    payload = b"A" * 200
    tlv = ASN1Builder().build_octet_string(payload)
    # Long-form marker: 0x81 (one length octet follows) then 0xC8 == 200.
    assert tlv[1] == 0x81
    assert ber_content(tlv) == payload


def test_ber_content_reproduces_old_bug_delta():
    """The fixed helper differs from the old naive slice for long-form."""
    payload = b"B" * 130
    tlv = ASN1Builder().build_octet_string(payload)
    naive = tlv[2:]  # the old, buggy behaviour
    assert naive != payload  # old slice was corrupt (kept a stray length octet)
    assert len(naive) == len(payload) + 1
    assert ber_content(tlv) == payload  # fixed helper is exact


def test_ber_content_too_short():
    """A TLV shorter than tag+length yields empty content, not an error."""
    assert ber_content(b"") == b""
    assert ber_content(b"\x04") == b""


def test_mms_read_request_large_varlist_is_well_formed():
    """A read request whose inner content exceeds 128B stays a valid [0] PDU.

    With the old ``[2:]`` bug the inner variable-list length would be off by
    the number of long-form length octets, corrupting every downstream field.
    """
    codec = MMSCodec()
    # 30 named objects pushes the encoded variable list well past 128 bytes.
    pdu = codec.build_read_request([(f"OBJ{i:03d}", "DOMAIN") for i in range(30)])
    # Confirmed-RequestPDU is context-specific [0] constructed (0xA0).
    assert pdu[0] == 0xA0

    # Decode the outer BER length and assert it equals the actual number of
    # content bytes — the invariant the old fixed-slice bug broke (the inner
    # length would be off by the count of long-form length octets).
    length_octet = pdu[1]
    if length_octet < 0x80:
        header_len, declared = 2, length_octet
    else:
        n = length_octet & 0x7F
        header_len = 2 + n
        declared = int.from_bytes(pdu[2 : 2 + n], "big")
    assert declared == len(pdu) - header_len, (
        f"declared BER length {declared} != actual content {len(pdu) - header_len}"
    )
