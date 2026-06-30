"""Unit KAT for the BACnet DCC/Reinit password parser.

tshark renders the (unnamed) password field as a bacapp ``text`` entry like
"Password: UTF-8 'secret'"; the listener pulls the quoted value out of it.
"""

import pytest

from oida.pcap.bacnet import BACnetPassiveListener


@pytest.mark.parametrize(
    "text, expected",
    [
        ("Password: UTF-8 'OIDA-ReinitPw1'", "OIDA-ReinitPw1"),
        ("Password: ASCII 'p@ssw0rd!'", "p@ssw0rd!"),
        ("Password: UTF-8 'with space'", "with space"),
        ("Password: UTF-8 'tail-quote''", "tail-quote'"),  # value contains a quote
        ("Context Tag: 0, Length/Value/Type: 1", None),  # not a password line
    ],
)
def test_bacnet_password_regex(text, expected):
    m = BACnetPassiveListener._PW_RE.search(text)
    assert (m.group(1) if m else None) == expected
