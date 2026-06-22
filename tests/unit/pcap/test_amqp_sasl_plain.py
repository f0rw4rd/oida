"""Regression test: AMQP SASL PLAIN credential extraction from FT_BYTES.

CODE_REVIEW finding (``src/oida/pcap/amqp.py``): _extract_sasl_credentials()
read ``amqp.method.arguments.response`` and passed it to _decode_auth_plain(),
which runs base64.b64decode() on it. But the AMQP SASL response is FT_BYTES in
tshark (packet-amqp.c), not a base64 string -- pyshark renders it as colon-hex
("00:75:73:65:72...") in PDML/XML mode or as a ``b'...'`` repr in EK mode. The
raw SASL PLAIN payload is the binary form ``\\x00user\\x00pass``. base64-decoding
the hex rendering either raised (silently caught -> ('','')) or produced garbage
without the NUL separators, so credentials were never recovered.

The fix decodes the FT_BYTES rendering to raw bytes and splits on b'\\x00'
directly. These tests drive the static decoder with constructed renderings (no
pyshark / tshark / .pcap fixture needed).
"""

import base64

from oida.pcap.amqp import AMQPPassiveListener


def _hex_colon(payload: bytes) -> str:
    """Render bytes the way pyshark FT_BYTES does in PDML/XML mode."""
    return ":".join(f"{b:02x}" for b in payload)


PLAIN_PAYLOAD = b"\x00user\x00pass"  # authzid="", authcid="user", passwd="pass"


def test_colon_hex_rendering_recovers_credentials():
    rendering = _hex_colon(PLAIN_PAYLOAD)
    assert rendering.startswith("00:75:73:65:72")  # \x00user...
    user, password = AMQPPassiveListener._decode_sasl_plain_response(rendering)
    assert (user, password) == ("user", "pass")


def test_plain_hex_no_colons_recovers_credentials():
    rendering = PLAIN_PAYLOAD.hex()  # "00757365720070617373"
    user, password = AMQPPassiveListener._decode_sasl_plain_response(rendering)
    assert (user, password) == ("user", "pass")


def test_bytes_repr_ek_mode_recovers_credentials():
    rendering = repr(PLAIN_PAYLOAD)  # "b'\\x00user\\x00pass'"
    assert rendering.startswith("b'")
    user, password = AMQPPassiveListener._decode_sasl_plain_response(rendering)
    assert (user, password) == ("user", "pass")


def test_base64_decode_of_hex_would_have_failed():
    """Document the old bug: base64-decoding the FT_BYTES rendering loses creds."""
    rendering = _hex_colon(PLAIN_PAYLOAD)
    # Old code path: base64.b64decode(rendering) on the hex string.
    try:
        decoded = base64.b64decode(rendering)
    except Exception:
        decoded = b""
    # The base64 path never yields exactly [authzid, authcid, passwd].
    assert decoded.split(b"\x00") != [b"", b"user", b"pass"]


def test_empty_response_returns_empty():
    assert AMQPPassiveListener._decode_sasl_plain_response("") == ("", "")


def test_malformed_rendering_returns_empty():
    assert AMQPPassiveListener._decode_sasl_plain_response("not-hex-zz") == ("", "")


def test_wrong_part_count_returns_empty():
    # Only one NUL separator -> 2 parts, not the 3 PLAIN requires.
    rendering = _hex_colon(b"user\x00pass")
    assert AMQPPassiveListener._decode_sasl_plain_response(rendering) == ("", "")
