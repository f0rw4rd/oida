"""Regression: IMAP AUTHENTICATE must surface the SASL mechanism.

``src/oida/pcap/imap.py`` (AUTHENTICATE branch, ~line 402) read a tshark
field named ``imap.request_parameter`` / ``request_parameter`` to populate
``detail["parameter"]`` with the SASL mechanism (PLAIN / LOGIN / CRAM-MD5 /
XOAUTH2, ...). That field does not exist in any Wireshark version -- the
complete registered ``imap.*`` field set (verified locally via
``tshark -G fields | grep -P '\\timap\\.'``) is:

    imap.command, imap.isrequest, imap.line, imap.request,
    imap.request.command, imap.request.command.uid, imap.request.folder,
    imap.request.password, imap.request.username, imap.request_tag,
    imap.response, imap.response.command, imap.response.status,
    imap.response_in, imap.response_tag, imap.response_to, imap.tag,
    imap.time

so ``get_field`` always returned the "" default and the operator-facing
"parameter" column for AUTHENTICATE was silently empty. The fix derives the
mechanism from ``imap.request`` (the "remainder of request line" per the
tshark field registry, e.g. "AUTHENTICATE PLAIN") instead.
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


def _authenticate_packet(request_text, request_command="AUTHENTICATE", tag="a1"):
    """Client -> server AUTHENTICATE request."""
    return _Packet(
        CLIENT_IP,
        SERVER_IP,
        CLIENT_PORT,
        IMAP_PORT,
        imap=_Layer(
            request_command=request_command,
            request=request_text,
            request_tag=tag,
        ),
    )


def _last_detail(listener):
    return listener.interactions[-1].details


def test_authenticate_plain_mechanism_is_extracted():
    """imap.request holds the 'remainder of request line' per the tshark
    field registry, e.g. "AUTHENTICATE PLAIN" (tag already stripped)."""
    listener = IMAPPassiveListener(interface="lo", timeout=1)
    listener.process_packet(_authenticate_packet("AUTHENTICATE PLAIN"))
    detail = _last_detail(listener)
    assert detail["parameter"] == "PLAIN"


def test_authenticate_cram_md5_mechanism_is_extracted():
    listener = IMAPPassiveListener(interface="lo", timeout=1)
    listener.process_packet(_authenticate_packet("AUTHENTICATE CRAM-MD5"))
    detail = _last_detail(listener)
    assert detail["parameter"] == "CRAM-MD5"


def test_authenticate_xoauth2_mechanism_is_extracted():
    listener = IMAPPassiveListener(interface="lo", timeout=1)
    listener.process_packet(_authenticate_packet("AUTHENTICATE XOAUTH2"))
    detail = _last_detail(listener)
    assert detail["parameter"] == "XOAUTH2"


def test_authenticate_mechanism_survives_trailing_crlf():
    listener = IMAPPassiveListener(interface="lo", timeout=1)
    listener.process_packet(_authenticate_packet("AUTHENTICATE LOGIN\r\n"))
    detail = _last_detail(listener)
    assert detail["parameter"] == "LOGIN"


def test_authenticate_mechanism_survives_full_line_with_tag_prefix():
    """Be defensive: if a caller ever supplies the full line (tag included)
    instead of just the remainder, the mechanism must still resolve."""
    listener = IMAPPassiveListener(interface="lo", timeout=1)
    listener.process_packet(_authenticate_packet("a1 AUTHENTICATE PLAIN"))
    detail = _last_detail(listener)
    assert detail["parameter"] == "PLAIN"


def test_authenticate_with_no_mechanism_does_not_set_bogus_parameter():
    """Bare AUTHENTICATE (client expects a server challenge next) must not
    surface the verb itself as a fake mechanism."""
    listener = IMAPPassiveListener(interface="lo", timeout=1)
    listener.process_packet(_authenticate_packet("AUTHENTICATE"))
    detail = _last_detail(listener)
    assert detail.get("parameter", "") != "AUTHENTICATE"
