"""Regression tests: refreshing a token must also re-arm its expiry.

``CryptoStateManager.get_token`` refreshed an expired token's ``value`` but left
``expires_at`` in the past, so ``is_expired()`` stayed True forever: every later
``get_token()``/``get_token_value()`` call invoked ``refresh_callback`` again --
an extra round trip (often a full re-auth) per message for the rest of the fuzz
session -- and callers checking ``is_expired()`` saw an expired token holding a
perfectly fresh value.
"""

from datetime import datetime, timedelta

from oida.fuzz.core.session.crypto_state import CryptoStateManager, TokenState


def _expired(**kwargs):
    return TokenState(
        name="session",
        value=b"stale",
        expires_at=datetime.now() - timedelta(seconds=1),
        **kwargs,
    )


def test_refresh_happens_once_not_on_every_lookup():
    calls = []

    def refresh():
        calls.append(1)
        return b"fresh"

    crypto = CryptoStateManager()
    crypto.set_token("session", _expired(refresh_callback=refresh))

    assert crypto.get_token_value("session") == b"fresh"
    assert crypto.get_token_value("session") == b"fresh"
    assert crypto.get_token_value("session") == b"fresh"

    assert len(calls) == 1
    assert crypto.get_token("session").is_expired() is False


def test_lifetime_rearms_expiry_window():
    crypto = CryptoStateManager()
    crypto.set_token(
        "session",
        _expired(refresh_callback=lambda: b"fresh", lifetime=timedelta(seconds=60)),
    )

    before = datetime.now()
    token = crypto.get_token("session")

    assert token.value == b"fresh"
    assert token.expires_at is not None
    assert token.expires_at > before
    assert token.is_expired() is False


def test_callback_returning_token_state_supplies_its_own_expiry():
    replacement = TokenState(
        name="session",
        value=b"fresh",
        expires_at=datetime.now() + timedelta(hours=1),
        metadata={"issuer": "server"},
    )

    crypto = CryptoStateManager()
    crypto.set_token("session", _expired(refresh_callback=lambda: replacement))

    token = crypto.get_token("session")

    assert token.value == b"fresh"
    assert token.expires_at == replacement.expires_at
    assert token.metadata["issuer"] == "server"


def test_failed_refresh_keeps_stale_value_and_retries():
    calls = []

    def refresh():
        calls.append(1)
        raise RuntimeError("server refused")

    crypto = CryptoStateManager()
    crypto.set_token("session", _expired(refresh_callback=refresh))

    # The stale value is still handed back, and the token stays expired so the
    # next lookup tries again rather than silently trusting stale material.
    assert crypto.get_token_value("session") == b"stale"
    assert crypto.get_token("session").is_expired() is True
    assert len(calls) == 2
