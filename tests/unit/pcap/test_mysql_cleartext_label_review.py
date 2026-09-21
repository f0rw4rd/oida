"""Regression: mysql_clear_password passwords were reported as an opaque hex hash.

With the ``mysql_clear_password`` client plugin (a WEAK_AUTH_PLUGINS member),
the ``mysql.passwd`` field bytes ARE the literal password -- yet the credential
was stored as raw hex and ``get_credentials_summary`` hardcoded
``credential_type: "hash"``, so the operator never saw the plaintext and
downstream tooling keying off credential_type missed a reusable cleartext
credential. Native-password plugins must keep their hash labeling untouched.
"""

import pytest

from oida.pcap.mysql import MySQLPassiveListener, MySQLSession

pytestmark = [pytest.mark.unit]


def _listener_with_session(plugin, password_bytes):
    listener = MySQLPassiveListener(interface="lo", timeout=1)
    session = MySQLSession(
        client_ip="10.0.0.10",
        server_ip="10.0.0.20",
        username="root",
        auth_plugin="mysql_native_password",
        client_auth_plugin=plugin,
        password_hash_hex=password_bytes.hex(),
    )
    listener._record_credential(session, success=True)
    return listener


def test_clear_password_plugin_reports_plaintext():
    listener = _listener_with_session("mysql_clear_password", b"s3cret")

    rows = listener.get_credentials_summary()
    assert len(rows) == 1
    row = rows[0]
    assert row["credential_type"] == "plaintext"
    assert row["password"] == "s3cret"


def test_native_password_plugin_still_reports_hash():
    listener = _listener_with_session("mysql_native_password", b"\xab" * 20)

    rows = listener.get_credentials_summary()
    assert len(rows) == 1
    row = rows[0]
    assert row["credential_type"] == "hash"
    assert row["password"] == (b"\xab" * 20).hex()


def test_cleartext_credential_dataclass_password_decoded():
    """The credential object itself carries the decoded password."""
    listener = _listener_with_session("mysql_clear_password", b"hunter2")

    assert len(listener.credentials) == 1
    cred = listener.credentials[0]
    assert cred.credential_type == "plaintext"
    assert cred.password == "hunter2"
