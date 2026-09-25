"""Regression tests for OSI primitive framing bugs (osi.py).

Bug 1: SessionConnectSPDU.encode() built the outer ISO 8327-1 SPDU header as
a bare single length byte (``bytes([si, li])``), with no extended-length
form. Fixed-parameter overhead is ~22 bytes, so ``li`` overflows a single
byte once user_data reaches ~232 bytes -- well before the inner PI=0xC1
sub-parameter's own 254-byte extended-length branch could ever kick in. That
made the inner branch dead code and crashed (or corrupted output via
truncation) any MMS association fuzzing that grew the Initiate Request past
~232 bytes.

Bug 2: TPKTHeader.encode() did no bounds checking on payload_length before
packing it into a 16-bit big-endian field, so payloads that push the total
TPKT length (4-byte header + payload) past 65535 raised a bare
struct.error instead of a clear, typed error.
"""

import pytest

from oida.fuzz.primitives.osi import (
    ISO8327_LONG_LI_MARKER,
    ISO8327_SHORT_LI_LIMIT,
    TPKT_MAX_PAYLOAD_LENGTH,
    SessionConnectSPDU,
    TPKTHeader,
)
from oida.utils.exceptions import ProtocolError

pytestmark = pytest.mark.core


# ---------------------------------------------------------------------------
# Regression guard: small/typical payload is byte-for-byte unchanged.
# ---------------------------------------------------------------------------


def test_session_connect_spdu_small_user_data_unchanged():
    """Small user_data keeps the exact pre-fix short-form encoding.

    Captured from the CURRENT (buggy) code before any edits:
        SessionConnectSPDU().encode(b"AB").hex()
        == "0d180506130100160102140200023302000134020001c1024142"
    """
    spdu = SessionConnectSPDU()
    out = spdu.encode(b"AB")
    expected = bytes.fromhex("0d180506130100160102140200023302000134020001c1024142")
    assert out == expected
    assert len(out) == 26
    # Short-form LI: byte[1] is a plain length, not the 0xFF marker.
    assert out[1] == 0x18
    assert out[1] == len(out) - 2


# ---------------------------------------------------------------------------
# Bug 1: outer SPDU header extended-length form.
# ---------------------------------------------------------------------------


def test_session_connect_spdu_user_data_230_short_form():
    """230-byte user_data: outer LI still fits in the 1-byte short form."""
    spdu = SessionConnectSPDU()
    out = spdu.encode(b"A" * 230)
    assert len(out) == 254
    li = out[1]
    assert li != ISO8327_LONG_LI_MARKER
    # LI must equal exactly the number of bytes that follow it.
    assert li == len(out) - 2


def test_session_connect_spdu_user_data_236_no_longer_raises():
    """236-byte user_data used to raise ValueError; must now encode cleanly."""
    spdu = SessionConnectSPDU()
    out = spdu.encode(b"A" * 236)
    assert out[1] == ISO8327_LONG_LI_MARKER
    extended_len = int.from_bytes(out[2:4], "big")
    assert extended_len == len(out) - 4
    assert out[4:] == out[4 : 4 + extended_len]


def test_session_connect_spdu_user_data_1000_extended_form_roundtrips():
    """1000-byte user_data: extended form length field matches trailing bytes."""
    spdu = SessionConnectSPDU()
    user_data = b"B" * 1000
    out = spdu.encode(user_data)
    assert out[1] == ISO8327_LONG_LI_MARKER
    extended_len = int.from_bytes(out[2:4], "big")
    assert extended_len == len(out) - 4
    # The trailing user_data bytes are present verbatim at the tail.
    assert out[-len(user_data) :] == user_data


def test_session_connect_spdu_user_data_65600_raises_typed_error():
    """65600-byte user_data used to raise a bare OverflowError from .to_bytes().

    It now exceeds the ISO 8327-1 2-byte extended-length maximum (65535) and
    must raise a clear ProtocolError instead.
    """
    spdu = SessionConnectSPDU()
    with pytest.raises(ProtocolError):
        spdu.encode(b"A" * 65600)


def test_session_connect_spdu_short_extended_boundary():
    """Pin the exact short/extended outer-LI boundary.

    Fixed overhead (Connect/Accept item, Session User Requirements, default
    selectors, PI=0xC1 sub-header) is 22 bytes when user_data < 255 bytes
    (the inner PI=0xC1 sub-parameter is still in its own short form). LI is a
    single octet for 0..254 -- only 0xFF is the extended-form marker -- so:
      - user_data = 232 bytes -> outer li == 254 (largest still short-form)
      - user_data = 233 bytes -> outer li == 255 (smallest needing extended)
    """
    spdu = SessionConnectSPDU()

    out_short = spdu.encode(b"A" * 232)
    assert out_short[1] == 254
    assert out_short[1] != ISO8327_LONG_LI_MARKER
    assert out_short[1] == len(out_short) - 2

    out_extended = spdu.encode(b"A" * 233)
    assert out_extended[1] == ISO8327_LONG_LI_MARKER
    extended_len = int.from_bytes(out_extended[2:4], "big")
    assert extended_len == ISO8327_SHORT_LI_LIMIT
    assert extended_len == len(out_extended) - 4


def test_session_connect_spdu_user_data_254_uses_short_inner_length():
    """The PI=0xC1 sub-parameter length is a single octet up to 254.

    254 used to trip the `< 254` split and emit the non-canonical three-octet
    form `FF 00 FE`; 0xFF is the only reserved LI value.
    """
    spdu = SessionConnectSPDU()
    out = spdu.encode(b"B" * 254)
    pi = out.index(b"\xc1", 2)
    assert out[pi + 1] == 254
    assert out[pi + 2 : pi + 6] == b"BBBB"

    # 255 is the first length that actually needs the extended form.
    out_ext = spdu.encode(b"B" * 255)
    pi = out_ext.index(b"\xc1", 2)
    assert out_ext[pi + 1] == ISO8327_LONG_LI_MARKER
    assert int.from_bytes(out_ext[pi + 2 : pi + 4], "big") == 255


# ---------------------------------------------------------------------------
# Bug 2: TPKTHeader bounds checking.
# ---------------------------------------------------------------------------


def test_tpkt_header_payload_zero():
    header = TPKTHeader()
    out = header.encode(0)
    assert out == bytes([0x03, 0x00, 0x00, 0x04])


def test_tpkt_header_payload_max_valid():
    """65531 is the largest payload whose 4-byte-header total fits in 16 bits."""
    header = TPKTHeader()
    assert TPKT_MAX_PAYLOAD_LENGTH == 65531
    out = header.encode(TPKT_MAX_PAYLOAD_LENGTH)
    total_length = int.from_bytes(out[2:4], "big")
    assert total_length == 65535
    assert total_length == 4 + TPKT_MAX_PAYLOAD_LENGTH


def test_tpkt_header_payload_one_over_max_raises_typed_error():
    """65532 used to raise a bare struct.error; must now be a ProtocolError."""
    header = TPKTHeader()
    with pytest.raises(ProtocolError):
        header.encode(TPKT_MAX_PAYLOAD_LENGTH + 1)


def test_tpkt_header_payload_far_over_max_raises_typed_error():
    header = TPKTHeader()
    with pytest.raises(ProtocolError):
        header.encode(70000)
