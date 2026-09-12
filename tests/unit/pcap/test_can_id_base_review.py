"""Regression test: CAN IDs must not be re-read as hexadecimal.

Repro basis (crafted SocketCAN capture /tmp/can5.pcap, tshark 4.4.15):

    <field name="can.id" showname="... = ID: 291 (0x00000123)" show="291"/>

tshark renders ``can.id`` in DECIMAL (both PDML ``show`` and the EK JSON value;
EK emits a bare int).  The listener parsed it with ``base=16``, so the frame
crafted with arbitration ID 0x123 (291) was recorded as 657 (0x291):

    XML ids= {'0x291': 1}   node ids= [657]
    EK  ids= {'0x291': 1}   node ids= [657]

Every CAN ID the listener reports was therefore wrong -- corrupting the unique-ID
inventory, ``top_ids``/``extended_ids`` and the ``can_id <= 0x00F`` high-priority
flood alert.  ``_parse_int`` still auto-detects a ``0x`` prefix, so dropping
``base=16`` keeps hex-rendered values working.
"""

from oida.pcap.can import CANPassiveListener


class _Layer:
    def __init__(self, name, **fields):
        self._layer_name = name
        self.layer_name = name
        for key, value in fields.items():
            setattr(self, key, value)

    def get_field_value(self, name, raw=False):
        return getattr(self, name.replace(".", "_"), None)


class _Packet:
    def __init__(self, can):
        self.can = can
        self.layers = [self.can]

    def __getattr__(self, item):
        raise AttributeError(item)


def _feed(**can_fields):
    listener = CANPassiveListener(interface="lo", timeout=1)
    listener.process_packet(_Packet(_Layer("can", **can_fields)))
    return listener


def test_decimal_can_id_is_not_reparsed_as_hex():
    """0x123 is rendered '291' by tshark; it must stay 291, not become 0x291."""
    listener = _feed(id="291", len="8", flags_xtd="True")
    assert list(listener._global_id_counts) == [0x123]


def test_decimal_can_id_ek_int_is_not_reparsed_as_hex():
    """EK mode hands over a native int."""
    listener = _feed(id=291, len="8", flags_xtd="True")
    assert list(listener._global_id_counts) == [0x123]


def test_hex_prefixed_can_id_still_parses():
    listener = _feed(id="0x123", len="8", flags_xtd="True")
    assert list(listener._global_id_counts) == [0x123]


def test_high_priority_alert_uses_the_real_id():
    """ID 10 (0x00A) is high-priority; base=16 turned it into 0x10 and missed it."""
    listener = _feed(id="10", len="8")
    assert listener._high_priority_count == 1


def test_canfd_id_is_not_reparsed_as_hex():
    listener = CANPassiveListener(interface="lo", timeout=1)
    pkt = _Packet(_Layer("can", len="8"))
    pkt.canfd = _Layer("canfd", id="291", len="8")
    pkt.layers = [pkt.can, pkt.canfd]
    listener.process_packet(pkt)
    assert list(listener._global_id_counts) == [0x123]
