"""Regression tests: IMAP session buffer must be bounded + dedup-at-source.

Every IMAP packet appended its
payload to ``session.data_buffer`` and then ran three ``re.DOTALL`` searches
over the ENTIRE accumulated buffer. The buffer was never trimmed, capped, or
cleared, so a long-lived / high-volume (peer-controlled) session grew it without
bound and the per-packet re-scan became O(n^2) regex work -- a passive-capture
DoS vector. The CRAM-MD5 / AUTH-PLAIN regexes also kept re-matching an
already-extracted credential on every subsequent packet.

The fix (a) caps ``data_buffer`` to the most recent ``MAX_BUFFER`` bytes and
(b) records a per-session "extracted" flag per auth method so the relevant
DOTALL search is no longer re-run once that credential has been recorded.

These tests drive ``process_packet`` with hand-built packet objects (no tshark
/ no pcap fixture), mirroring ``test_smtp_imap_nonstandard_port.py``.
"""

import pytest

from oida.pcap.imap import IMAPPassiveListener

pytestmark = [pytest.mark.unit]


class _Layer:
    """Minimal stand-in for a pyshark layer (plain attribute bag)."""

    def __init__(self, **fields):
        self.__dict__.update(fields)


class _Packet:
    """Minimal stand-in for a pyshark packet with ip/tcp + imap layers."""

    def __init__(self, src_ip, dst_ip, src_port, dst_port, **layers):
        self.ip = _Layer(src=src_ip, dst=dst_ip)
        self.tcp = _Layer(srcport=src_port, dstport=dst_port, stream="0")
        for name, layer in layers.items():
            setattr(self, name, layer)


SERVER_IP = "10.0.0.10"
CLIENT_IP = "10.0.0.20"
IMAP_PORT = 143
CLIENT_PORT = 52000


def _client_payload_packet(payload: str) -> _Packet:
    """Client -> server packet carrying raw request data (no parsed command)."""
    return _Packet(
        CLIENT_IP,
        SERVER_IP,
        CLIENT_PORT,
        IMAP_PORT,
        imap=_Layer(request=payload),
    )


def test_data_buffer_is_bounded_under_high_volume():
    """A flood of non-credential request data must NOT grow the session buffer
    without bound. Before the fix the buffer grew by ~1 KB per packet forever;
    after the fix it is capped at MAX_BUFFER bytes."""
    listener = IMAPPassiveListener(interface="lo", timeout=1)

    chunk = "X" * 1024  # 1 KB of benign filler per packet
    n_packets = 200  # ~200 KB total on the wire
    for _ in range(n_packets):
        listener.process_packet(_client_payload_packet(chunk))

    session = listener._sessions[(CLIENT_IP, SERVER_IP)]
    assert len(session.data_buffer) <= listener.MAX_BUFFER, (
        f"data_buffer grew to {len(session.data_buffer)} bytes "
        f"(> MAX_BUFFER={listener.MAX_BUFFER}); unbounded growth not capped"
    )
    # Sanity: the cap must be a real bound, well below total bytes pushed.
    assert listener.MAX_BUFFER < n_packets * len(chunk)


def test_cram_md5_regex_not_rerun_after_extraction():
    """Once a CRAM-MD5 credential is recorded for a session, the (expensive)
    DOTALL search must not be re-run on subsequent packets. Before the fix it
    re-searched the whole buffer every packet and re-matched the same already
    -extracted credential."""
    listener = IMAPPassiveListener(interface="lo", timeout=1)

    # A complete CRAM-MD5 exchange in one buffer (challenge + response + OK).
    # response is base64 of "alice 0123456789abcdef0123456789abcdef".
    import base64

    challenge = base64.b64encode(b"<challenge@host>").decode()
    response = base64.b64encode(b"alice 0123456789abcdef0123456789abcdef").decode()
    exchange = (
        f"a001 AUTHENTICATE CRAM-MD5\r\n"
        f"+ {challenge}\r\n"
        f"{response}\r\n"
        f"a001 OK CRAM-MD5 authentication successful\r\n"
    )
    listener.process_packet(_client_payload_packet(exchange))

    creds = listener.get_credentials_summary()
    assert len(creds) == 1, "CRAM-MD5 credential not extracted"
    assert creds[0]["auth_method"] == "CRAM-MD5"

    session = listener._sessions[(CLIENT_IP, SERVER_IP)]
    assert "CRAM-MD5" in session.extracted, "per-session extracted flag not set"

    # Count regex .search calls on subsequent packets: must stay zero.
    calls = {"n": 0}
    orig_pattern = listener.IMAP_CRAM_MD5_REGEX

    class _Wrapper:
        def search(self, text):
            calls["n"] += 1
            return orig_pattern.search(text)

    listener.IMAP_CRAM_MD5_REGEX = _Wrapper()
    try:
        for _ in range(10):
            listener.process_packet(_client_payload_packet("more benign data\r\n"))
    finally:
        listener.IMAP_CRAM_MD5_REGEX = orig_pattern

    assert calls["n"] == 0, (
        f"CRAM-MD5 regex re-run {calls['n']} times after credential already extracted"
    )
    # And no duplicate credential was recorded.
    assert len(listener.get_credentials_summary()) == 1


def test_login_buffer_fallback_not_rerun_after_pyshark_extraction():
    """A LOGIN credential extracted via PyShark direct fields must set the
    session 'extracted' flag so the buffer-fallback DOTALL search is skipped on
    later packets (no redundant re-scan / re-match)."""
    listener = IMAPPassiveListener(interface="lo", timeout=1)

    pkt = _Packet(
        CLIENT_IP,
        SERVER_IP,
        CLIENT_PORT,
        IMAP_PORT,
        imap=_Layer(
            request_command="LOGIN",
            request_tag="a001",
            request_username="alice",
            request_password="s3cret",
            request="a001 LOGIN alice s3cret",
        ),
    )
    listener.process_packet(pkt)

    assert len(listener.get_credentials_summary()) == 1
    session = listener._sessions[(CLIENT_IP, SERVER_IP)]
    assert "LOGIN" in session.extracted

    calls = {"n": 0}
    orig_pattern = listener.IMAP_PLAINTEXT_LOGIN_REGEX

    class _Wrapper:
        def search(self, text):
            calls["n"] += 1
            return orig_pattern.search(text)

    listener.IMAP_PLAINTEXT_LOGIN_REGEX = _Wrapper()
    try:
        # Re-feed the same LOGIN line via the raw buffer path.
        listener.process_packet(_client_payload_packet("a001 LOGIN alice s3cret\r\na001 OK\r\n"))
    finally:
        listener.IMAP_PLAINTEXT_LOGIN_REGEX = orig_pattern

    assert calls["n"] == 0, "LOGIN DOTALL search re-run after credential already extracted"
    assert len(listener.get_credentials_summary()) == 1
