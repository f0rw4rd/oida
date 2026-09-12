"""Regression test: unbounded SMTPSession.data_buffer growth (passive-capture DoS).

Once the substring "CRAM-MD5" has appeared anywhere in a session's
data_buffer, every subsequent packet carrying a command/response field is
appended to that buffer forever (``smtp.py`` around the "CRAM-MD5
accumulation" block), and the accumulated buffer is re-scanned in full by
SMTP_CRAM_MD5_REGEX.search() on every single packet. The buffer is only ever
reset on a *successful AUTH LOGIN* extraction -- a CRAM-MD5 session never
takes that path, so for a long-lived / high-volume capture this is
unbounded memory growth plus O(n^2) CPU from re-scanning an ever-growing
buffer per packet: a passive-capture DoS.

imap.py fixed the identical pattern with a MAX_BUFFER sliding-window trim
(see imap.py's IMAPPassiveListener.MAX_BUFFER and the trim right after
``session.data_buffer += packet_data``). This test drives the real SMTP
listener through a CRAM-MD5 trigger followed by many more command/response
packets and asserts the buffer stays bounded -- and, as a control, that
legitimate CRAM-MD5 credential harvesting still works after the fix.
"""

import pytest

from oida.pcap.smtp import SMTPPassiveListener

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


SERVER_IP = "10.0.0.10"
CLIENT_IP = "10.0.0.20"
SERVER_PORT = 25
CLIENT_PORT = 52000

# Well-known base64 CRAM-MD5 challenge/response pair (format is irrelevant to
# the listener beyond matching the regex's charset).
CHALLENGE_B64 = "PDQxOTI5NDIzMTQwOTQ3OTQ1NjZAc2VydmVyLmV4YW1wbGU+"
# Decodes (per _extract_cram_md5_username) as "alice <hex digest>"
RESPONSE_B64 = "YWxpY2UgZDVhM2NjMWQzZTdhMTljZjZhNGY3ZDljOWQwOWYyZjY="


def _client_cmd(command, parameter=""):
    return _Packet(
        CLIENT_IP,
        SERVER_IP,
        CLIENT_PORT,
        SERVER_PORT,
        smtp=_Layer(req_command=command, req_parameter=parameter),
    )


def _server_rsp(code, param=""):
    return _Packet(
        SERVER_IP,
        CLIENT_IP,
        SERVER_PORT,
        CLIENT_PORT,
        smtp=_Layer(response_code=code, rsp_parameter=param),
    )


class TestSMTPDataBufferBounded:
    def test_buffer_stays_bounded_after_cram_md5_trigger(self):
        listener = SMTPPassiveListener(interface="lo", timeout=1)

        # Trigger: get "CRAM-MD5" into the buffer.
        listener.process_packet(_client_cmd("AUTH", "CRAM-MD5"))
        session = listener._sessions[(CLIENT_IP, SERVER_IP)]
        assert "CRAM-MD5" in session.data_buffer

        # Flood: many more command/response packets on the same session,
        # each of which appends to data_buffer per the vulnerable code path.
        for i in range(2000):
            listener.process_packet(_server_rsp("250", f"OK line {i} padding padding padding"))

        # A single 100 Bytes/day-modem is nothing, but the buffer must be
        # capped to a bounded sliding window regardless of session length --
        # this is the DoS fix under test.
        assert len(session.data_buffer) <= 8192, (
            f"SMTPSession.data_buffer grew unbounded: {len(session.data_buffer)} bytes "
            "-- passive-capture DoS (O(n^2) CPU + unbounded RSS)"
        )

    def test_cram_md5_credential_still_extracted_after_fix(self):
        """Control: capping the buffer must not break legitimate CRAM-MD5 harvesting."""
        listener = SMTPPassiveListener(interface="lo", timeout=1)

        listener.process_packet(_client_cmd("AUTH", "CRAM-MD5"))
        listener.process_packet(_server_rsp("334", CHALLENGE_B64))
        # Bare response line: no command/response_code field in real
        # captures, but the harness here needs *some* signal to reach the
        # accumulation block -- use a 235 success response that carries the
        # base64 hash line as part of the same accumulated buffer by also
        # feeding it as a command line (mirrors how tshark exposes stray
        # AUTH continuation lines with an smtp layer but odd fields in
        # practice; what matters is that data_buffer ends up containing the
        # full "AUTH CRAM-MD5\r\n334 ...\r\n<hash>\r\n235" sequence the
        # regex expects).
        listener.process_packet(_client_cmd(RESPONSE_B64))
        listener.process_packet(_server_rsp("235"))

        creds = listener.get_credentials_summary()
        assert len(creds) >= 1, "CRAM-MD5 credential extraction broke after buffer-cap fix"
        cred = creds[0]
        assert cred["auth_method"] == "CRAM-MD5"
        assert cred["username"] == "alice"
