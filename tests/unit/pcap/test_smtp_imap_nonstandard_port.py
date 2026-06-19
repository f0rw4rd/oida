"""Regression tests: SMTP/IMAP direction on non-standard ports.

Both listeners historically decided client/server direction by a hardcoded
standard port (SMTP 25/587/465, IMAP 143/993) with a bare ``else: return``.
Sessions captured on a non-standard port (a remapped submission port, an IMAP
proxy port, etc.) still match the ``smtp``/``imap`` display filter but matched
neither port test, so the packet was silently dropped.

The fix adds a "lower port wins" fallback (the listening server side has the
smaller fixed port vs. the ephemeral client port), mirroring the iec104/mms
heuristic. These tests feed hand-built packet objects directly to
``process_packet`` so they need neither tshark nor a pcap fixture.
"""

import pytest

from oida.pcap.passive.imap import IMAPPassiveListener
from oida.pcap.passive.smtp import SMTPPassiveListener

pytestmark = [pytest.mark.unit]


class _Layer:
    """Minimal stand-in for a pyshark layer (plain attribute bag)."""

    def __init__(self, **fields):
        self.__dict__.update(fields)


class _Packet:
    """Minimal stand-in for a pyshark packet with ip/tcp + protocol layers."""

    def __init__(self, src_ip, dst_ip, src_port, dst_port, **layers):
        self.ip = _Layer(src=src_ip, dst=dst_ip)
        self.tcp = _Layer(srcport=src_port, dstport=dst_port, stream="0")
        for name, layer in layers.items():
            setattr(self, name, layer)


# Server uses a non-standard port; client is on a high ephemeral port.
SERVER_IP = "10.0.0.10"
CLIENT_IP = "10.0.0.20"
NONSTD_SMTP_PORT = 2525  # not in (25, 587, 465)
NONSTD_IMAP_PORT = 1430  # not in (143, 993)
CLIENT_PORT = 52000


class TestSMTPNonStandardPort:
    def test_client_command_on_nonstandard_port_recorded_as_request(self):
        listener = SMTPPassiveListener(interface="lo", timeout=1)
        # Client -> server (dst is the lower, non-standard server port).
        pkt = _Packet(
            CLIENT_IP,
            SERVER_IP,
            CLIENT_PORT,
            NONSTD_SMTP_PORT,
            smtp=_Layer(req_command="EHLO", req_parameter="client.example"),
        )
        listener.process_packet(pkt)

        assert listener.interactions, "non-standard-port SMTP packet was dropped"
        req = [ix for ix in listener.interactions if ix.direction == "request"]
        assert req, "client command not recorded as a request on non-standard port"
        # Session must be keyed with the correct client/server orientation.
        assert (CLIENT_IP, SERVER_IP) in listener._sessions
        session = listener._sessions[(CLIENT_IP, SERVER_IP)]
        assert session.server_port == NONSTD_SMTP_PORT

    def test_server_response_on_nonstandard_port_recorded_as_response(self):
        listener = SMTPPassiveListener(interface="lo", timeout=1)
        # Server -> client (src is the lower, non-standard server port).
        pkt = _Packet(
            SERVER_IP,
            CLIENT_IP,
            NONSTD_SMTP_PORT,
            CLIENT_PORT,
            smtp=_Layer(response_code="220", rsp_parameter="mail.example ESMTP"),
        )
        listener.process_packet(pkt)

        assert listener.interactions, "non-standard-port SMTP response was dropped"
        resp = [ix for ix in listener.interactions if ix.direction == "response"]
        assert resp, "server response not recorded as a response on non-standard port"
        # Banner must be attributed to the server IP, not the client.
        assert SERVER_IP in listener.server_banners

    def test_standard_port_behavior_unchanged(self):
        listener = SMTPPassiveListener(interface="lo", timeout=1)
        pkt = _Packet(
            CLIENT_IP,
            SERVER_IP,
            CLIENT_PORT,
            25,
            smtp=_Layer(req_command="EHLO", req_parameter="client.example"),
        )
        listener.process_packet(pkt)
        assert (CLIENT_IP, SERVER_IP) in listener._sessions
        assert listener._sessions[(CLIENT_IP, SERVER_IP)].server_port == 25


class TestIMAPNonStandardPort:
    def test_client_command_on_nonstandard_port_recorded_as_request(self):
        listener = IMAPPassiveListener(interface="lo", timeout=1)
        # Client -> server (dst is the lower, non-standard server port).
        pkt = _Packet(
            CLIENT_IP,
            SERVER_IP,
            CLIENT_PORT,
            NONSTD_IMAP_PORT,
            imap=_Layer(request_command="CAPABILITY", request_tag="a001"),
        )
        listener.process_packet(pkt)

        assert listener.interactions, "non-standard-port IMAP packet was dropped"
        req = [ix for ix in listener.interactions if ix.direction == "request"]
        assert req, "client command not recorded as a request on non-standard port"
        assert (CLIENT_IP, SERVER_IP) in listener._sessions

    def test_login_credential_extracted_on_nonstandard_port(self):
        listener = IMAPPassiveListener(interface="lo", timeout=1)
        pkt = _Packet(
            CLIENT_IP,
            SERVER_IP,
            CLIENT_PORT,
            NONSTD_IMAP_PORT,
            imap=_Layer(
                request_command="LOGIN",
                request_tag="a001",
                request_username="alice",
                request_password="s3cret",
            ),
        )
        listener.process_packet(pkt)

        creds = listener.get_credentials_summary()
        assert len(creds) >= 1, "LOGIN credential dropped on non-standard IMAP port"
        cred = creds[0]
        assert cred["username"] == "alice"
        assert cred["server_ip"] == SERVER_IP
        assert cred["client_ip"] == CLIENT_IP

    def test_server_banner_on_nonstandard_port(self):
        listener = IMAPPassiveListener(interface="lo", timeout=1)
        # Server -> client (src is the lower, non-standard server port).
        pkt = _Packet(
            SERVER_IP,
            CLIENT_IP,
            NONSTD_IMAP_PORT,
            CLIENT_PORT,
            imap=_Layer(line="* OK Dovecot ready.", response_status="OK"),
        )
        listener.process_packet(pkt)

        assert listener.interactions, "non-standard-port IMAP response was dropped"
        resp = [ix for ix in listener.interactions if ix.direction == "response"]
        assert resp, "server response not recorded as a response on non-standard port"
        assert SERVER_IP in listener.server_banners

    def test_standard_port_behavior_unchanged(self):
        listener = IMAPPassiveListener(interface="lo", timeout=1)
        pkt = _Packet(
            CLIENT_IP,
            SERVER_IP,
            CLIENT_PORT,
            143,
            imap=_Layer(request_command="CAPABILITY", request_tag="a001"),
        )
        listener.process_packet(pkt)
        assert (CLIENT_IP, SERVER_IP) in listener._sessions
