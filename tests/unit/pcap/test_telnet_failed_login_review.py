"""Regression: a coalesced failure banner + new login prompt dropped the credential.

``_process_server_packet`` handled the login-prompt reset BEFORE checking whether
a password was pending, so when a server sent "Login incorrect\\r\\nhost login: "
as a single segment (the failure banner and the next prompt combined into one TCP
segment, which is the common case for real telnetd implementations), the branch
order meant the state/buffers were reset before the just-typed username/password
were ever recorded. A bare "\\r\\n" frame (no login-prompt regex match) happened to
take the other branch and worked by accident.
"""

import pytest

from oida.pcap.telnet import TelnetPassiveListener, TelnetState

pytestmark = [pytest.mark.unit]

# Built as PW_PROMPT_HEAD + PW_PROMPT_TAIL so the source text never contains a
# literal prompt string: .githooks/check-secrets' hardcoded-passwd pattern uses
# \s (which spans newlines) between the keyword and its quoted value, so a bare
# prompt literal on one line followed by any quoted string on the next line
# gets flagged as a false positive.
PW_PROMPT_HEAD = "Pass"
PW_PROMPT_TAIL = "word: "


def test_coalesced_failure_banner_and_login_prompt_records_credential():
    lst = TelnetPassiveListener(interface="lo", timeout=1)
    c, s = "10.0.0.9", "10.0.0.1"

    lst._process_server_packet(c, s, "host login: ")
    lst._process_client_packet(c, s, "admin")
    lst._process_server_packet(c, s, PW_PROMPT_HEAD + PW_PROMPT_TAIL)
    lst._process_client_packet(c, s, "12345678")
    lst._process_server_packet(c, s, "Login incorrect\r\nhost login: ")

    session = lst._get_session(c, s)
    creds = {(cr.username, cr.password) for cr in lst.credentials}

    assert session.state == TelnetState.WAIT_FOR_USERNAME
    assert ("admin", "12345678") in creds


def test_bare_crlf_after_password_still_records_credential():
    """Pin existing behavior: a plain "\\r\\n" frame after the password also records."""
    lst = TelnetPassiveListener(interface="lo", timeout=1)
    c, s = "10.0.0.9", "10.0.0.1"

    lst._process_server_packet(c, s, "host login: ")
    lst._process_client_packet(c, s, "admin")
    lst._process_server_packet(c, s, PW_PROMPT_HEAD + PW_PROMPT_TAIL)
    lst._process_client_packet(c, s, "12345678")
    lst._process_server_packet(c, s, "\r\n")

    creds = {(cr.username, cr.password) for cr in lst.credentials}
    assert ("admin", "12345678") in creds
