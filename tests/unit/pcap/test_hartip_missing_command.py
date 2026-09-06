"""Regression test: HART-IP pass-through frame with no pt_command field.

CODE_REVIEW finding (``src/oida/pcap/hartip.py`` ~line 416-417): the command
field was parsed as
``command = self._parse_int(self.get_field(hart_layer, "pt_command"))``.
``get_field`` returns None for an absent field, but ``_parse_int(None)`` uses
its ``default=0`` (NOT None), so ``command`` was ALWAYS an int and the guard
``if command is None: return`` could never fire. A pass-through frame in which
tshark did not populate ``pt_command`` was therefore mis-classified as command
0 ("Read Unique Identifier") -- fabricating an interaction and polluting
``session.commands_seen`` / device-identity extraction.

The fix passes ``default=None`` explicitly so the existing guard works, and
does the same for ``pt_short_addr`` / ``pt_delimiter_address_type`` so their
``is not None`` / ``== 1`` checks reflect true field presence.

These tests drive ``process_packet()`` with lightweight fake packets (no
pyshark / tshark / pcap fixture needed).
"""

from oida.pcap.hartip import (
    MSG_ID_PASS_THROUGH,
    MSG_TYPE_REQUEST,
    HARTIPPassiveListener,
)


class _Layer:
    """Minimal stand-in for a pyshark layer: attribute access only.

    Only the fields explicitly passed exist; absent fields fall back to the
    getattr default in get_field(), exactly like a dissector that did not emit
    them.
    """

    def __init__(self, **fields):
        for k, v in fields.items():
            setattr(self, k, v)


class _FakePacket:
    def __init__(self, src_ip, dst_ip, src_mac, dst_mac, src_port, dst_port, hart_ip_fields):
        self.eth = _Layer(src=src_mac, dst=dst_mac)
        self.ip = _Layer(src=src_ip, dst=dst_ip)
        self.udp = _Layer(srcport=str(src_port), dstport=str(dst_port))
        self.hart_ip = _Layer(**hart_ip_fields)


HOST_IP = "10.0.0.5"
DEVICE_IP = "10.0.0.10"
HOST_MAC = "aa:bb:cc:00:00:01"
DEVICE_MAC = "aa:bb:cc:00:00:02"
HARTIP_PORT = 5094


def _make_listener():
    return HARTIPPassiveListener(interface="lo", timeout=1)


def _request_pass_through(hart_ip_fields):
    """Host -> device pass-through request on the HART-IP server port."""
    return _FakePacket(
        src_ip=HOST_IP,
        dst_ip=DEVICE_IP,
        src_mac=HOST_MAC,
        dst_mac=DEVICE_MAC,
        src_port=49152,
        dst_port=HARTIP_PORT,
        hart_ip_fields=hart_ip_fields,
    )


def test_pass_through_without_command_is_skipped():
    """A pass-through frame whose pt_command field is absent must be skipped --
    not recorded as command 0 ("Read Unique Identifier")."""
    listener = _make_listener()

    listener.process_packet(
        _request_pass_through(
            {
                "message_type": MSG_TYPE_REQUEST,
                "message_id": MSG_ID_PASS_THROUGH,
                # NO pt_command field -- this is the regression case.
            }
        )
    )

    assert listener.interactions == [], (
        "pass-through frame with no pt_command was recorded as an interaction "
        "(mis-classified as command 0)"
    )
    # No session should have been created / polluted either.
    for session in listener.sessions.values():
        assert 0 not in session.commands_seen, "command 0 was fabricated into session.commands_seen"


def test_pass_through_with_command_is_recorded():
    """Control: a pass-through frame that DOES carry pt_command is recorded with
    that command (proves the guard does not over-reject)."""
    listener = _make_listener()

    listener.process_packet(
        _request_pass_through(
            {
                "message_type": MSG_TYPE_REQUEST,
                "message_id": MSG_ID_PASS_THROUGH,
                "pt_command": "3",  # Read Dynamic Variables
            }
        )
    )

    assert len(listener.interactions) == 1, "valid pass-through command was dropped"
    assert listener.interactions[-1].details["command"] == 3

    session = next(iter(listener.sessions.values()))
    assert 3 in session.commands_seen
    assert 0 not in session.commands_seen
