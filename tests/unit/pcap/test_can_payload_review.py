"""Regression test: the CAN payload must actually be extracted.

Repro basis (crafted SocketCAN capture, tshark 4.4.15):

- XML mode dissects the payload as the generic ``data`` proto's ``data.data`` --
  a *sibling* layer of ``can``. ``can.data`` is not a valid display filter.
- EK mode emits ``layers: {"data": {"data_data_data": "11:22:..."},
  "can": {...}}``.

The listener used to read ``get_field(can_layer, "data")``, which resolves to
nothing in either mode, so ``data_hex`` -- surfaced in details, summary and the
protocol columns -- was always empty (silently; ``get_field`` swallows misses).
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
    def __init__(self, can, data=None):
        self.can = can
        if data is not None:
            self.data = data
        self.layers = [self.can] + ([self.data] if data is not None else [])
        # AttributeError -> hasattr() False for `data` when absent

    def __getattr__(self, item):
        raise AttributeError(item)


def _can_layer(**fields):
    return _Layer("can", **fields)


def _listener():
    return CANPassiveListener(interface="lo", timeout=1)


def _feed(can_fields, data_fields=None):
    listener = _listener()
    pkt = _Packet(_can_layer(**can_fields), _Layer("data", **(data_fields or {})))
    listener.process_packet(pkt)
    return listener


def test_payload_is_read_from_the_data_layer_ek_spelling():
    listener = _feed(
        {"id": "291", "len": "8", "flags_xtd": "True"},
        {"data_data_data": "11:22:33:44:55:66:77:88"},
    )
    details = listener.interactions[0].details
    assert details["data_hex"] == "11 22 33 44 55 66 77 88"


def test_payload_is_read_from_the_data_layer_xml_spelling():
    listener = _feed(
        {"id": "291", "len": "8", "flags_xtd": "True"},
        {"data_data": "11:22:33:44:55:66:77:88"},
    )
    assert listener.interactions[0].details["data_hex"] == "11 22 33 44 55 66 77 88"


def test_payload_missing_on_data_layer_is_not_fatal():
    listener = _feed({"id": "291", "len": "8", "flags_xtd": "True"}, {})
    assert "data_hex" not in listener.interactions[0].details


def test_payload_reaches_the_summary():
    listener = _feed(
        {"id": "291", "len": "8", "flags_xtd": "True"},
        {"data_data_data": "11:22:33:44:55:66:77:88"},
    )
    assert "11 22 33" in listener.interactions[0].summary


def test_rtr_frame_has_no_payload():
    listener = _feed(
        {"id": "291", "len": "0", "flags_rtr": "True"},
        {"data_data_data": "11:22"},
    )
    assert "data_hex" not in listener.interactions[0].details


def test_payloadless_frame_has_no_empty_key():
    listener = _feed({"id": "291", "len": "0"})
    assert "data_hex" not in listener.interactions[0].details
