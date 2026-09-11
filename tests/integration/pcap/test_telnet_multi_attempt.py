"""Regression: Telnet session regex must not span multiple login attempts.

The line-mode fallback used a greedy pattern (``login:([\\s\\S]*)password:(.*)``).
When a buffer held a failed login followed by a retry, the greedy span matched
from the FIRST ``login:`` to the LAST ``password:``, pairing the first username
with the last password -- a fabricated credential that was never sent. The
pattern is now lazy and iterated, so each attempt is captured and paired
correctly.
"""

import pytest

from oida.pcap.telnet import TelnetPassiveListener, TelnetSession

pytestmark = [pytest.mark.integration]


def _session(buffer):
    s = TelnetSession(client_ip="10.0.0.9", server_ip="10.0.0.1")
    s.client_buffer = buffer
    return s


def _creds(listener):
    return {(c.username, c.password) for c in listener.credentials}


def test_two_attempts_paired_correctly():
    listener = TelnetPassiveListener(interface="lo", timeout=1)
    buffer = "login: baduser\r\npassword: badpass\r\nlogin: gooduser\r\npassword: goodpass\r\n"
    session = _session(buffer)

    listener._try_session_match(session)

    creds = _creds(listener)
    # Each attempt paired with its own password; no cross-attempt fabrication.
    assert ("baduser", "badpass") in creds
    assert ("gooduser", "goodpass") in creds
    # The greedy bug produced this fabricated pairing -- it must not appear.
    assert ("baduser", "goodpass") not in creds


def test_single_attempt_still_works():
    listener = TelnetPassiveListener(interface="lo", timeout=1)
    session = _session("login: admin\r\npassword: secret\r\n")

    listener._try_session_match(session)

    assert ("admin", "secret") in _creds(listener)
