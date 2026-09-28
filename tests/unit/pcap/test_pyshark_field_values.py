"""Regression tests for PySharkListenerBase.get_field_values().

get_field_values() was added for GH issue #62: get_field() comma-joins
multi-value pyshark fields into one scalar, which fused N answer records
of one DNS packet into single bogus hostname keys (e.g.
"google.com,example.com" as a mapping key). These tests pin the split
behavior, the scalar/list/bytes coercions, and the miss/default path.
"""

from __future__ import annotations


from oida.pcap.pyshark_base import PySharkListenerBase


class _FakeLayer:
    """Stands in for a pyshark layer: plain attribute lookups."""

    def __init__(self, **fields):
        self._fields = fields

    def __getattr__(self, name):
        try:
            return self.__dict__["_fields"][name]
        except KeyError:
            raise AttributeError(name)


class _Listener(PySharkListenerBase):
    """Concrete subclass: PySharkListenerBase is abstract."""

    PROTOCOL_NAME = "test"
    DISPLAY_FILTER = ""

    def process_packet(self, packet) -> None:  # pragma: no cover - unused here
        pass


def _listener():
    import logging

    return _Listener(interface="lo", timeout=1, nxc_logger=logging.getLogger("test"))


class TestGetFieldValues:
    def test_scalar_string_becomes_one_element_list(self):
        listener = _listener()
        layer = _FakeLayer(a="216.239.37.26")
        assert listener.get_field_values(layer, "a") == ["216.239.37.26"]

    def test_comma_joined_scalar_is_split_per_record(self):
        """The #62 bug itself: pyshark joins multi-value fields with commas."""
        listener = _listener()
        layer = _FakeLayer(a="1.1.1.1,2.2.2.2,3.3.3.3")
        assert listener.get_field_values(layer, "a") == ["1.1.1.1", "2.2.2.2", "3.3.3.3"]

    def test_list_field_becomes_per_element_list(self):
        listener = _listener()
        layer = _FakeLayer(a=["1.1.1.1", "2.2.2.2"])
        assert listener.get_field_values(layer, "a") == ["1.1.1.1", "2.2.2.2"]

    def test_list_of_bytes_is_hexed(self):
        listener = _listener()
        layer = _FakeLayer(payload=b"\xde\xad")
        assert listener.get_field_values(layer, "payload") == ["de:ad"]

    def test_scalar_bytes_is_hexed(self):
        listener = _listener()
        layer = _FakeLayer(payload=b"\x01\x02")
        assert listener.get_field_values(layer, "payload") == ["01:02"]

    def test_int_field_becomes_string(self):
        listener = _listener()
        layer = _FakeLayer(flags=123)
        assert listener.get_field_values(layer, "flags") == ["123"]

    def test_missing_field_returns_default(self):
        listener = _listener()
        layer = _FakeLayer(a="x")
        assert listener.get_field_values(layer, "nope", default=[]) == []

    def test_get_field_still_comma_joins_for_display(self):
        """get_field()'s join is fine for display; the split lives in
        get_field_values(). Pins the asymmetry so the two don't drift."""
        listener = _listener()
        layer = _FakeLayer(a="1.1.1.1,2.2.2.2")
        assert listener.get_field(layer, "a") == "1.1.1.1,2.2.2.2"
