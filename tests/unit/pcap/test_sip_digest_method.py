"""Regression test: SIP digest hashcat (mode 11400) must use the real request
method, not a hardcoded REGISTER.

CODE_REVIEW finding (``src/oida/pcap/sip.py``): both
``SIPDigestCredential.hashcat_format`` and
``SIPPassiveListener.get_hashcat_hashes()`` emitted the digest with the SIP
method hardcoded to ``REGISTER``. Hashcat 11400 folds the request method into
HA2 (``md5(method:uri)``), so an Authorization header captured from an INVITE /
BYE / SUBSCRIBE would crack against the wrong HA2 and silently produce
useless credentials.

The fix threads the SIP CSeq method (the method the digest was computed over)
into ``_extract_digest_auth``, stores it on the credential, and substitutes it
for the hardcoded ``REGISTER`` in both hashcat emitters.

Fixture-free: drives ``_extract_digest_auth`` with a minimal fake pyshark
layer (no tshark / .pcap needed).
"""

from oida.pcap.sip import SIPDigestCredential, SIPPassiveListener


class _Layer:
    """Minimal pyshark-layer stand-in: only the passed fields exist."""

    def __init__(self, **fields):
        for k, v in fields.items():
            setattr(self, k, v)


def _auth_layer(method_unused=None):
    # The auth_* fields are all _extract_digest_auth reads; the method is a
    # separate argument (sourced from CSeq in process_packet).
    return _Layer(
        auth_username="alice",
        auth_realm="asterisk",
        auth_nonce="abc123",
        auth_digest_response="deadbeefcafef00ddeadbeefcafef00d",
        auth_uri="sip:bob@example.com",
        auth_qop="auth",
        auth_nc="00000001",
        auth_cnonce="cnonce123",
        auth_algorithm="MD5",
    )


def _make_listener():
    return SIPPassiveListener(interface="lo", timeout=1)


def test_invite_digest_uses_invite_in_hashcat():
    """An INVITE-derived digest must emit INVITE (not REGISTER) in mode 11400."""
    listener = _make_listener()
    listener._extract_digest_auth(
        _auth_layer(), src_ip="10.0.0.5", dst_ip="10.0.0.10", dst_port=5060, method="INVITE"
    )

    hashes = listener.get_hashcat_hashes()
    assert len(hashes) == 1
    h = hashes[0]
    assert "*INVITE*" in h, f"expected INVITE in hashcat hash, got: {h}"
    assert "*REGISTER*" not in h, f"hardcoded REGISTER leaked into INVITE hash: {h}"
    # hashcat 11400 layout: method is field 5; the line ends with the directive
    # (MD5) then the response digest.
    assert h.endswith("*MD5*deadbeefcafef00ddeadbeefcafef00d")


def test_register_digest_still_uses_register():
    """REGISTER stays REGISTER (the common case must not regress)."""
    listener = _make_listener()
    listener._extract_digest_auth(
        _auth_layer(), src_ip="10.0.0.5", dst_ip="10.0.0.10", dst_port=5060, method="REGISTER"
    )
    assert "*REGISTER*" in listener.get_hashcat_hashes()[0]


def test_method_defaults_to_register_when_absent():
    """Backward-compat: callers that omit method get the historic REGISTER."""
    listener = _make_listener()
    listener._extract_digest_auth(
        _auth_layer(), src_ip="10.0.0.5", dst_ip="10.0.0.10", dst_port=5060
    )
    cred = listener.credentials[0]
    assert cred.method == "REGISTER"
    assert "*REGISTER*" in cred.hashcat_format


def test_credential_method_stored_and_in_property():
    """The credential carries the method and its hashcat_format property uses it."""
    cred = SIPDigestCredential(
        username="alice",
        realm="asterisk",
        nonce="abc123",
        uri="sip:bob@example.com",
        response="deadbeef",
        qop="auth",
        nc="00000001",
        cnonce="cnonce123",
        algorithm="MD5",
        method="SUBSCRIBE",
    )
    assert "*SUBSCRIBE*" in cred.hashcat_format
    assert cred.hashcat_format.endswith("*MD5*deadbeef")
    assert "*REGISTER*" not in cred.hashcat_format
