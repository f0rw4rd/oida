"""Regression test: an FTP-layer packet carrying neither a request_command nor a
response_code must not be silently dropped.

CODE_REVIEW finding ``src/oida/pcap/ftp.py:150-207``: process_packet()
recorded an interaction only inside the ``if request_command:`` and
``if response_code:`` branches. An ftp-layer packet with neither field set (e.g. a
tshark continuation segment of a multi-line response, or a reassembled frame where
tshark attaches the ftp layer without re-emitting ftp.response.code) fell off the
end of the function with no interaction recorded and no explanatory debug log --
the silent-drop bug class. The fix adds a trailing branch that emits a debug log.

These tests drive process_packet() with a lightweight fake packet (no pyshark /
tshark needed): a well-formed command/response still records an interaction, while
a field-less ftp frame records nothing but logs at debug level.
"""

from oida.pcap.ftp import FTPPassiveListener


class _Layer:
    """Minimal stand-in for a pyshark layer: attribute access only."""

    def __init__(self, **fields):
        for k, v in fields.items():
            setattr(self, k, v)


class _FakePacket:
    """Minimal stand-in for a pyshark packet for FTP process_packet()."""

    def __init__(self, src_ip, dst_ip, src_port, dst_port, ftp_fields):
        self.ip = _Layer(src=src_ip, dst=dst_ip)
        self.tcp = _Layer(srcport=src_port, dstport=dst_port, stream="0")
        self.ftp = _Layer(**ftp_fields)


def _make_listener():
    return FTPPassiveListener(interface="lo", timeout=1)


CLIENT = "10.0.0.5"
SERVER = "10.0.0.10"


def test_ftp_frame_without_command_or_response_is_not_dropped_silently():
    """An ftp frame with neither request_command nor response_code records no
    interaction but emits an explanatory debug log instead of vanishing.

    The listener's logger has ``propagate=False`` and its own handler, so it is
    not visible to pytest's ``caplog``; assert on the logger directly via a mock.
    """
    listener = _make_listener()

    debug_calls = []
    listener.logger.debug = lambda msg, *a, **k: debug_calls.append(msg)

    listener.process_packet(
        _FakePacket(
            src_ip=SERVER,
            dst_ip=CLIENT,
            src_port=21,
            dst_port=50000,
            # ftp layer present, but no request_command / response_code field
            # (e.g. a reassembly/continuation segment).
            ftp_fields={"current_working_directory": "/pub"},
        )
    )

    assert listener.interactions == [], "field-less ftp frame should not record an interaction"
    assert any("no recognized" in msg for msg in debug_calls), (
        "expected a debug log noting the unrecognized ftp frame was not recorded"
    )


def test_ftp_request_still_records_interaction():
    """Guard: the normal command path still records an interaction (the fix must
    not break well-formed traffic)."""
    listener = _make_listener()

    listener.process_packet(
        _FakePacket(
            src_ip=CLIENT,
            dst_ip=SERVER,
            src_port=50000,
            dst_port=21,
            ftp_fields={"request_command": "USER", "request_arg": "anonymous"},
        )
    )

    assert len(listener.interactions) == 1, "well-formed FTP command was not recorded"


def test_ftp_response_still_records_interaction():
    """Guard: the normal response path still records an interaction."""
    listener = _make_listener()

    listener.process_packet(
        _FakePacket(
            src_ip=SERVER,
            dst_ip=CLIENT,
            src_port=21,
            dst_port=50000,
            ftp_fields={"response_code": "220", "response_arg": "Welcome"},
        )
    )

    assert len(listener.interactions) == 1, "well-formed FTP response was not recorded"
