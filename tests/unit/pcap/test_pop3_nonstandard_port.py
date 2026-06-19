"""Regression test: POP3 listener must not silently drop non-standard-port sessions.

CODE_REVIEW finding `src/oida/pcap/passive/pop3.py:207-311`: process_packet()
gated the entire interaction record on `dst_port in (110, 995)` /
`src_port in (110, 995)` with no else branch, so a POP3 session on any
non-standard port (stunnel wrappers, lab setups, containers mapping
1100/8110, etc.) matched the `pop` display filter but fell through both
branches — no interaction recorded, no debug log.

These tests drive process_packet() with lightweight fake packets (no pyshark
/ tshark needed) and assert that POP3 on a non-standard port is still
processed and directionally correct.
"""

from oida.pcap.passive.pop3 import POP3PassiveListener


class _Layer:
    """Minimal stand-in for a pyshark layer: attribute access only."""

    def __init__(self, **fields):
        # The listener reads fields via get_field(layer, "request_command", ...)
        # which is getattr(layer, "request_command"); store them directly.
        for k, v in fields.items():
            setattr(self, k, v)


class _FakePacket:
    """Minimal stand-in for a pyshark packet for POP3 process_packet()."""

    def __init__(self, src_ip, dst_ip, src_port, dst_port, pop_fields):
        self.ip = _Layer(src=src_ip, dst=dst_ip)
        self.tcp = _Layer(srcport=src_port, dstport=dst_port, stream="0")
        self.pop = _Layer(**pop_fields)


def _make_listener():
    return POP3PassiveListener(interface="lo", timeout=1)


def test_pop3_request_on_nonstandard_port_recorded():
    """Client -> server USER command on a remapped port (1100) is recorded.

    Client ephemeral port 54321 -> server listening port 1100. The server is
    the lower port, so this must be treated as a request and the interaction
    recorded (not dropped).
    """
    listener = _make_listener()

    pkt = _FakePacket(
        src_ip="10.0.0.5",
        dst_ip="10.0.0.10",
        src_port=54321,
        dst_port=1100,
        pop_fields={"request_command": "USER", "request_parameter": "alice"},
    )
    listener.process_packet(pkt)

    assert listener.interactions, "POP3 packet on non-standard port was dropped (no interaction)"
    ix = listener.interactions[-1]
    assert ix.direction == "request"
    assert ix.src_port == 54321
    assert ix.dst_port == 1100
    # Direction-derived session bookkeeping must have happened: the USER
    # command updates the session username and creates a client device.
    assert any(s.username == "alice" for s in listener._sessions.values()), (
        "USER command on non-standard port was not processed into a session"
    )


def test_pop3_response_on_nonstandard_port_recorded():
    """Server -> client +OK banner on a remapped port (1100) is recorded.

    Server listening port 1100 -> client ephemeral 54321. The server is the
    lower port and is the source, so this must be treated as a response.
    """
    listener = _make_listener()

    pkt = _FakePacket(
        src_ip="10.0.0.10",
        dst_ip="10.0.0.5",
        src_port=1100,
        dst_port=54321,
        pop_fields={
            "response_indicator": "+OK",
            "response_description": "POP3 server ready",
        },
    )
    listener.process_packet(pkt)

    assert listener.interactions, "POP3 response on non-standard port was dropped"
    ix = listener.interactions[-1]
    assert ix.direction == "response"
    assert ix.src_port == 1100
    assert ix.dst_port == 54321
    # Banner should have been captured from the server side.
    assert listener.server_banners.get("10.0.0.10") == "POP3 server ready"


def test_pop3_standard_port_still_request():
    """Sanity: standard port 110 still classifies dst as the server (request)."""
    listener = _make_listener()

    pkt = _FakePacket(
        src_ip="10.0.0.5",
        dst_ip="10.0.0.10",
        src_port=40000,
        dst_port=110,
        pop_fields={"request_command": "USER", "request_parameter": "bob"},
    )
    listener.process_packet(pkt)

    assert listener.interactions
    assert listener.interactions[-1].direction == "request"
    assert any(s.username == "bob" for s in listener._sessions.values())
