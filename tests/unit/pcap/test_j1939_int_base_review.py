"""Regression: J1939 CAN identifier must not be re-read as hexadecimal.

Same bug class as ``tests/unit/pcap/test_can_id_base_review.py``:
``j1939.can_id`` is the same masked 29-bit CAN arbitration identifier field
as ``can.id``, which was proven (crafted SocketCAN capture, tshark 4.4.15)
to render in DECIMAL in both PDML ``show``/``showname`` and EK JSON, even
though the field is declared BASE_HEX. ``_parse_int(raw, default, base=16)``
then re-read that decimal string as hex, corrupting the identifier (e.g.
0x123 == decimal 291 was re-read as 0x291 == 657).

``_parse_int`` still auto-detects a leading ``0x``, so dropping ``base=16``
keeps hex-rendered (XML/PDML) values working identically.
"""

from oida.pcap.j1939 import J1939PassiveListener


class _Layer:
    def __init__(self, **fields):
        for k, v in fields.items():
            setattr(self, k, v)


class _Packet:
    def __init__(self, j1939):
        self.j1939 = j1939
        self.eth = _Layer(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee")
        self.transport_layer = ""
        self.highest_layer = "J1939"

    def __contains__(self, item):
        return hasattr(self, str(item).lower())


def _feed(**fields):
    listener = J1939PassiveListener(interface="lo", timeout=1)
    base_fields = dict(
        priority="6",
        pgn="61444",
        src_addr="0",
        pdu_format="0",
        pdu_specific="4",
    )
    base_fields.update(fields)
    listener.process_packet(_Packet(_Layer(**base_fields)))
    return listener


def test_decimal_can_id_is_not_reparsed_as_hex():
    """0x123 is rendered '291' by tshark; it must stay 0x123, not become 0x291."""
    listener = _feed(can_id="291")
    ix = listener.interactions[0]
    assert ix.details["can_id"] == "0x00000123"


def test_decimal_can_id_ek_int_is_not_reparsed_as_hex():
    """EK mode hands over a native int, normalized to str by get_field()."""
    listener = _feed(can_id=291)
    ix = listener.interactions[0]
    assert ix.details["can_id"] == "0x00000123"


def test_hex_prefixed_can_id_still_parses():
    listener = _feed(can_id="0x123")
    ix = listener.interactions[0]
    assert ix.details["can_id"] == "0x00000123"
