"""Regression: a missing/garbage PostgreSQL MD5 salt must not be emitted.

`src/oida/pcap/pgsql.py` `_handle_auth_request_msg()` stored the literal
placeholder ``"?"`` in ``session.salt`` when the AuthenticationMD5Password
message carried no ``pgsql.salt`` field.  That placeholder is truthy, so it
flowed into the Auth interaction details, into ``PostgreSQLCredential.salt``,
into the JSON/hashcat export and into the console line as ``salt=?`` -- an
operator (or a downstream cracking script) cannot tell it apart from a real
4-byte server salt.

A PostgreSQL MD5 salt is 4 raw bytes; tshark renders it as hex, optionally
separated by ':' or ','.  Anything that is not hex after separator stripping
is not a salt and must be dropped rather than reported.

Driven directly against `_handle_auth_request_msg()` with a lightweight fake
layer (no pyshark / tshark needed), mirroring test_pgsql_sasl_mechanism.py.
"""

import pytest

from oida.pcap.pgsql import AUTH_MD5, PostgreSQLCredential, PostgreSQLPassiveListener


class _Layer:
    """Minimal stand-in for a pyshark layer: attribute access only."""

    def __init__(self, **fields):
        for k, v in fields.items():
            setattr(self, k, v)


def _drive_md5_auth(listener, layer, fields=None):
    listener._handle_auth_request_msg(
        now="2026-01-01T00:00:00",
        client_ip="10.0.0.5",
        client_port=54321,
        server_ip="10.0.0.10",
        server_port=5432,
        server_mac="aa:bb:cc:dd:ee:ff",
        pgsql_layer=layer,
        fields=fields if fields is not None else {},
        flow_id="0",
    )


def _last_auth_interaction(listener):
    auths = [ix for ix in listener.interactions if ix.operation.startswith("Auth")]
    assert auths, "AUTH_MD5 request produced no interaction"
    return auths[-1]


def _session(listener):
    assert listener._sessions, "no session tracked"
    return next(iter(listener._sessions.values()))


def test_missing_salt_is_not_reported_as_placeholder():
    """No pgsql.salt field -> no salt detail, and never the literal '?'."""
    listener = PostgreSQLPassiveListener(interface="lo", timeout=1)
    _drive_md5_auth(listener, _Layer(authtype=str(AUTH_MD5)))

    ix = _last_auth_interaction(listener)
    assert ix.details.get("salt") != "?", "placeholder '?' leaked into Auth details"
    assert not ix.details.get("salt"), f"bogus salt reported: {ix.details.get('salt')!r}"
    assert _session(listener).salt in ("", None), "placeholder '?' stored on the session"


@pytest.mark.parametrize("bogus", ["?", "not-a-salt", "zzzz", "unknown"])
def test_non_hex_salt_is_rejected(bogus):
    """A salt that is not hex after separator stripping must be dropped."""
    listener = PostgreSQLPassiveListener(interface="lo", timeout=1)
    _drive_md5_auth(listener, _Layer(authtype=str(AUTH_MD5), salt=bogus))

    ix = _last_auth_interaction(listener)
    assert not ix.details.get("salt"), f"non-hex salt {bogus!r} was reported"
    assert _session(listener).salt in ("", None)


@pytest.mark.parametrize("good", ["9a:2b:3c:4d", "9A2B3C4D", "9a,2b,3c,4d"])
def test_real_hex_salt_is_kept(good):
    """A genuine 4-byte hex salt (any tshark separator style) survives."""
    listener = PostgreSQLPassiveListener(interface="lo", timeout=1)
    _drive_md5_auth(listener, _Layer(authtype=str(AUTH_MD5), salt=good))

    ix = _last_auth_interaction(listener)
    assert ix.details.get("salt"), f"real salt {good!r} was dropped"
    assert _session(listener).salt


def test_hashcat_line_suppressed_for_placeholder_salt():
    """Defence in depth: the credential itself refuses a non-hex salt."""
    cred = PostgreSQLCredential(
        username="oida",
        database="postgres",
        password_or_hash="md5" + "de" * 16,
        salt="?",
        auth_type="md5",
        server_ip="10.0.0.10",
        client_ip="10.0.0.5",
        success=None,
        timestamp="2026-01-01T00:00:00",
    )
    assert cred.hashcat_format == ""
