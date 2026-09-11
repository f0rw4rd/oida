"""Regression tests for the encode()/decode() codec-mismatch bug in the
text-based encoding transformers.

Bug: URLEncodeTransformer, HTMLEntityTransformer, JSONEscapeTransformer, and
XMLEscapeTransformer all decoded raw input bytes with a "try UTF-8, fall
back to Latin-1" strategy, but then unconditionally re-encoded the result
with UTF-8 -- regardless of which codec actually decoded the input. When
the Latin-1 fallback fired (i.e. the input was not valid UTF-8), every byte
>= 0x80 got turned into a *two-byte* UTF-8 sequence on the way back out,
silently corrupting the payload before it ever reaches the wire.

These tests were written against the pre-fix code (see the captured
fail-before output in the task report) and pin:
  * full round-trip fidelity for bytes(range(256)) through each of the
    four classes,
  * the specific documented case, URLEncodeTransformer b"\\xff" -> b"%FF",
  * sane behaviour on empty / single-ASCII-byte input,
  * a regression guard: pure-ASCII and valid-multi-byte-UTF-8 payloads must
    produce byte-for-byte identical encode() output to the pre-fix code
    (values captured from the code before any changes were made),
  * that Base64Transformer / HexTransformer (unaffected, byte-oriented)
    still round-trip the full byte range.
"""

import pytest

from oida.fuzz.primitives.transformers.encoding import (
    Base64Transformer,
    HexTransformer,
    HTMLEntityTransformer,
    JSONEscapeTransformer,
    URLEncodeTransformer,
    XMLEscapeTransformer,
)

TEXT_TRANSFORMER_CLASSES = [
    URLEncodeTransformer,
    HTMLEntityTransformer,
    JSONEscapeTransformer,
    XMLEscapeTransformer,
]

FULL_RANGE = bytes(range(256))

# Captured from the CURRENT (pre-fix) code, before any changes were made in
# this session, via direct inline reproduction:
#
#   ascii_payload = b'Hello World! 123'
#   utf8_payload = 'café é <tag> "quoted" & more'.encode('utf-8')
#
#   URLEncodeTransformer ascii enc= b'Hello%20World%21%20123'
#   URLEncodeTransformer utf8  enc= b'caf%C3%A9%20%C3%A9%20%3Ctag%3E%20%22quoted%22%20%26%20more'
#   HTMLEntityTransformer ascii enc= b'Hello World! 123'
#   HTMLEntityTransformer utf8  enc= b'caf\xc3\xa9 \xc3\xa9 &lt;tag&gt; &quot;quoted&quot; &amp; more'
#   JSONEscapeTransformer ascii enc= b'Hello World! 123'
#   JSONEscapeTransformer utf8  enc= b'caf\\u00e9 \\u00e9 <tag> \\"quoted\\" & more'
#   XMLEscapeTransformer ascii enc= b'Hello World! 123'
#   XMLEscapeTransformer utf8  enc= b'caf\xc3\xa9 \xc3\xa9 &lt;tag&gt; &quot;quoted&quot; &amp; more'
#
# These four "enc=" values are unaffected by the codec-mismatch bug (ASCII
# passes through identically under either codec, and the valid-UTF-8 case
# happened to already round-trip through the old unconditional UTF-8
# re-encode). The fix MUST NOT change any of them.
ASCII_PAYLOAD = b"Hello World! 123"
UTF8_PAYLOAD = 'café é <tag> "quoted" & more'.encode("utf-8")

REGRESSION_ENCODE_BASELINE = {
    URLEncodeTransformer: {
        ASCII_PAYLOAD: b"Hello%20World%21%20123",
        UTF8_PAYLOAD: b"caf%C3%A9%20%C3%A9%20%3Ctag%3E%20%22quoted%22%20%26%20more",
    },
    HTMLEntityTransformer: {
        ASCII_PAYLOAD: b"Hello World! 123",
        UTF8_PAYLOAD: b"caf\xc3\xa9 \xc3\xa9 &lt;tag&gt; &quot;quoted&quot; &amp; more",
    },
    JSONEscapeTransformer: {
        ASCII_PAYLOAD: b"Hello World! 123",
        UTF8_PAYLOAD: b'caf\\u00e9 \\u00e9 <tag> \\"quoted\\" & more',
    },
    XMLEscapeTransformer: {
        ASCII_PAYLOAD: b"Hello World! 123",
        UTF8_PAYLOAD: b"caf\xc3\xa9 \xc3\xa9 &lt;tag&gt; &quot;quoted&quot; &amp; more",
    },
}


@pytest.mark.parametrize("cls", TEXT_TRANSFORMER_CLASSES)
def test_full_byte_range_round_trips(cls):
    """decode(encode(x)) must reproduce every byte 0x00-0xFF exactly.

    Before the fix this failed for all four classes: encode() decoded the
    non-UTF-8 input via the Latin-1 fallback, then unconditionally
    re-encoded with UTF-8, expanding every byte >= 0x80 into two bytes.
    """
    transformer = cls()
    encoded = transformer.encode(FULL_RANGE)
    decoded = transformer.decode(encoded)
    assert decoded == FULL_RANGE, (
        f"{cls.__name__} failed to round-trip the full byte range; "
        f"first mismatch context: decoded[:20]={decoded[:20]!r}"
    )


def test_url_encode_high_byte_is_single_percent_pair():
    """Documented, specifically-required case: a lone 0xFF byte must encode
    to exactly b"%FF" (one raw byte), not b"%C3%BF" (a spurious two-byte
    UTF-8 re-encode of the Latin-1-decoded character)."""
    assert URLEncodeTransformer().encode(b"\xff") == b"%FF"


@pytest.mark.parametrize("cls", TEXT_TRANSFORMER_CLASSES)
def test_empty_and_single_ascii_byte_behave_sanely(cls):
    transformer = cls()
    assert transformer.encode(b"") == b""
    # A bare ASCII letter needs no escaping in any of these four schemes.
    assert transformer.encode(b"A") == b"A"
    # And it must still round-trip.
    assert transformer.decode(transformer.encode(b"A")) == b"A"
    assert transformer.decode(transformer.encode(b"")) == b""


@pytest.mark.parametrize("cls", TEXT_TRANSFORMER_CLASSES)
def test_ascii_and_valid_utf8_encode_output_unchanged(cls):
    """Regression guard: the fix must not alter encode() output for
    pure-ASCII or valid-multi-byte-UTF-8 input -- only the Latin-1-fallback
    path (non-UTF-8 bytes) was buggy."""
    baseline = REGRESSION_ENCODE_BASELINE[cls]
    transformer = cls()
    assert transformer.encode(ASCII_PAYLOAD) == baseline[ASCII_PAYLOAD]
    assert transformer.encode(UTF8_PAYLOAD) == baseline[UTF8_PAYLOAD]


@pytest.mark.parametrize("cls", [Base64Transformer, HexTransformer])
def test_byte_oriented_transformers_unaffected(cls):
    """Base64Transformer and HexTransformer operate on raw bytes directly
    and were never affected by the text-codec bug; they must continue to
    round-trip the full byte range both before and after the fix."""
    transformer = cls()
    assert transformer.decode(transformer.encode(FULL_RANGE)) == FULL_RANGE
