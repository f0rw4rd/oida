"""Regression test for X11 MIT-MAGIC-COOKIE-1 cookie corruption
(src/oida/pcap/x11.py, ``_process_connection_request``, ~line 293-330).

pyshark decodes the binary auth-data (cookie) field with ``errors=replace``,
so ``x11.authorization-protocol-data`` always comes back as a string with
U+FFFD replacement characters wherever a cookie byte fell outside the
printable/latin-1-safe range. The code then tried
``raw_str.encode("latin-1")`` to turn that string back into hex -- which
ALWAYS raises ``UnicodeEncodeError`` for a mangled string containing
U+FFFD (0xFFFD has no latin-1 representation) -- and the except-branch
stored the corrupted string itself as the "hex" credential value. The real
16-byte cookie is still recoverable byte-for-byte from the raw TCP payload
of the same connection-request packet.
"""

import shutil

import pytest

pyshark = pytest.importorskip("pyshark")

from oida.pcap.x11 import X11PassiveListener  # noqa: E402

pytestmark = pytest.mark.skipif(not shutil.which("tshark"), reason="tshark not available")

FIXTURE = "tests/fixtures/pcap/x11/generated_x11.pcap"
TRUE_COOKIE_HEX = "a1b2c3d4e5f6789012345678abcdef01"


def _load_x11_credentials():
    listener = X11PassiveListener(interface="lo", timeout=1)
    cap = pyshark.FileCapture(
        FIXTURE,
        use_ek=True,
        custom_parameters={"-o": "tcp.desegment_tcp_streams:TRUE"},
    )
    try:
        for pkt in cap:
            listener.process_packet(pkt)
    finally:
        cap.close()
    return listener.get_credentials_summary()


def test_mit_magic_cookie_recovered_verbatim_not_mojibake():
    creds = _load_x11_credentials()
    assert len(creds) >= 1, f"Expected >= 1 X11 credential, got {len(creds)}"

    cookie_creds = [c for c in creds if c.get("auth_method") == "MIT-MAGIC-COOKIE-1"]
    assert cookie_creds, f"Expected a MIT-MAGIC-COOKIE-1 credential; got: {creds}"

    auth_data = cookie_creds[0]["auth_data"]
    # Must be the exact 32-hex-char wire cookie, not a mangled/replacement
    # string (mojibake would fail this equality and would also fail to be
    # valid hex).
    assert auth_data == TRUE_COOKIE_HEX
    bytes.fromhex(auth_data)  # must be valid hex -- would raise on mojibake
