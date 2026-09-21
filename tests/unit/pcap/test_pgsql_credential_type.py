"""Regression test: PGSQL credential summary must not call every auth type plaintext.

``PostgreSQLPassiveListener.get_credentials_summary()`` inlined its own
``credential_type`` mapping instead of using the
``PostgreSQLCredential.credential_type`` property. The inlined chain named only
``md5`` ("hash") and ``cleartext`` ("plaintext") and fell through to
"plaintext" for everything else -- so a SASL/SCRAM exchange (no password on the
wire) and a passwordless ``trust`` login (``auth_type == "none"``) were both
reported as recovered plaintext credentials. The pcap scanner prints anything
typed "plaintext" as a ``user:password`` pair, so the summary claimed
credentials that were never captured, and it disagreed with the property the
same scanner loop reads off the credential object.
"""

import pytest

from oida.pcap.pgsql import PostgreSQLCredential, PostgreSQLPassiveListener


def _credential(auth_type, password_or_hash=""):
    return PostgreSQLCredential(
        username="postgres",
        database="ics",
        password_or_hash=password_or_hash,
        salt=None,
        auth_type=auth_type,
        server_ip="10.0.0.10",
        client_ip="10.0.0.5",
        success=True,
    )


def _summary_for(auth_type, password_or_hash=""):
    listener = PostgreSQLPassiveListener(interface="lo", timeout=1)
    listener.credentials.append(_credential(auth_type, password_or_hash))
    summary = listener.get_credentials_summary()
    assert len(summary) == 1
    return summary[0]


@pytest.mark.parametrize(
    "auth_type,expected",
    [
        ("cleartext", "plaintext"),
        ("md5", "hash"),
        ("sasl", "none"),
        ("none", "none"),
    ],
)
def test_summary_credential_type_matches_auth_type(auth_type, expected):
    assert _summary_for(auth_type)["credential_type"] == expected


@pytest.mark.parametrize("auth_type", ["sasl", "none"])
def test_passwordless_auth_is_not_reported_as_plaintext(auth_type):
    """SASL/SCRAM and trust logins put no password on the wire."""
    assert _summary_for(auth_type)["credential_type"] != "plaintext"


@pytest.mark.parametrize("auth_type", ["cleartext", "md5", "sasl", "none"])
def test_summary_agrees_with_credential_property(auth_type):
    """The summary must not drift from the property the scanner loop reads."""
    cred = _credential(auth_type)
    listener = PostgreSQLPassiveListener(interface="lo", timeout=1)
    listener.credentials.append(cred)

    assert listener.get_credentials_summary()[0]["credential_type"] == cred.credential_type
