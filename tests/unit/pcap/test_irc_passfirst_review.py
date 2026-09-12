"""Regression: an IRC PASS seen before NICK/USER must not print the password
as the username.

``get_credentials_summary`` in ``src/oida/pcap/irc.py`` computed
``username = cred.nick or cred.username or cred.value``.  For a PASS
credential, ``cred.value`` IS the password.  RFC 2812 sec. 3.1 registers the
connection as PASS -> NICK -> USER, so when PASS arrives first the session has
neither nick nor user yet and both are ``""`` -- the fallback then rendered the
server password in the credential table's *username* column (next to the same
string in the password column).

The shipped fixture sends NICK, USER, PASS in that order, so
``test_irc_passive.py`` never exercises the documented real-world ordering.
"""

from oida.pcap.irc import IRCPassiveListener


class _Layer:
    def __init__(self, **fields):
        for k, v in fields.items():
            setattr(self, k, v)


class _Packet:
    def __init__(self, command, parameter):
        self.irc = _Layer(
            request_command=command,
            request_command_parameter=parameter,
        )
        self.ip = _Layer(src="10.0.0.5", dst="10.0.0.9")
        self.tcp = _Layer(srcport="51000", dstport="6667", stream="0")
        self.eth = _Layer(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee")
        self.transport_layer = "TCP"
        self.highest_layer = "IRC"

    def __contains__(self, item):
        return hasattr(self, str(item).lower())


PASSWORD = "s3cr3t-server-pw"


def _run(order):
    listener = IRCPassiveListener(interface="lo", timeout=1)
    for command, parameter in order:
        listener.process_packet(_Packet(command, parameter))
    return listener


RFC2812_ORDER = [
    ("PASS", PASSWORD),
    ("NICK", "alice"),
    ("USER", "aliceuser 0 * :Alice Liddell"),
]

FIXTURE_ORDER = [
    ("NICK", "alice"),
    ("USER", "aliceuser 0 * :Alice Liddell"),
    ("PASS", PASSWORD),
]


def _plaintext_entries(listener):
    return [
        e for e in listener.get_credentials_summary() if e["credential_type"] == "plaintext"
    ]


def test_pass_first_does_not_leak_password_as_username():
    entries = _plaintext_entries(_run(RFC2812_ORDER))
    assert entries, "PASS credential not captured"
    for e in entries:
        assert e["username"] != PASSWORD, (
            "the server password was rendered in the username column "
            f"({e['username']!r}) because PASS preceded NICK/USER"
        )


def test_pass_first_still_reports_the_password():
    """The fix must not lose the credential -- only the username column."""
    entries = _plaintext_entries(_run(RFC2812_ORDER))
    assert any(e["password"] == PASSWORD for e in entries)


def test_fixture_order_still_attributes_the_nick():
    """NICK-before-PASS (the shipped fixture order) keeps working."""
    entries = _plaintext_entries(_run(FIXTURE_ORDER))
    assert entries
    assert any(e["username"] == "alice" for e in entries)


def test_no_plaintext_entry_claims_username_equal_to_password():
    for order in (RFC2812_ORDER, FIXTURE_ORDER):
        for e in _plaintext_entries(_run(order)):
            assert not (e["username"] and e["username"] == e["password"])
