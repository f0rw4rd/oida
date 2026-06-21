"""Smoke tests for the devicenet passive listener.

No reference pcap is bundled for devicenet yet; these tests verify the
listener module loads cleanly, the class is importable, the
REQUIRED_LAYERS contract is set, and harvest() returns the expected
dict shape on an empty session. Once a reference pcap fixture is
added under ``tests/fixtures/pcap/devicenet/`` upgrade this file to use
``_run_listener_test`` with real packet-level assertions.
"""

import pytest

pytestmark = [pytest.mark.integration]


class TestDeviceNetPassiveSmoke:
    """devicenet listener smoke tests (no fixture pcap)."""

    def test_class_importable(self):
        import oida.pcap.devicenet as mod

        cls = getattr(mod, "DeviceNetPassiveListener", None)
        assert cls is not None, (
            "DeviceNetPassiveListener not exported from oida.pcap.devicenet"
        )

    def test_required_layers_set(self):
        from oida.pcap.devicenet import DeviceNetPassiveListener

        required = getattr(DeviceNetPassiveListener, "REQUIRED_LAYERS", None)
        assert required, "REQUIRED_LAYERS must be set so the listener registers a filter"
        assert "devicenet" in required or len(required) > 0

    def test_harvest_shape_on_empty(self):
        from oida.pcap.devicenet import DeviceNetPassiveListener

        listener = DeviceNetPassiveListener(interface="lo", timeout=1)
        listener._x509 = True
        result = listener.harvest()
        assert isinstance(result, dict), "harvest() must return a dict"


class _FakeLayer:
    """Minimal stand-in for a pyshark layer (attribute -> value)."""

    def __init__(self, **fields):
        for k, v in fields.items():
            setattr(self, k, v)


class TestDeviceNetEKDecimalParsing:
    """Regression: EK-mode BASE_HEX fields arrive as DECIMAL strings.

    Forcing base=16 reparsed an EK decimal like "16" as hex 0x16=22. The fix
    drops base=16 so CIP class/instance/attribute/vendor round-trip correctly.
    """

    def test_cip_class_ek_decimal_not_reparsed_as_hex(self):
        from oida.pcap.devicenet import DeviceNetPassiveListener

        listener = DeviceNetPassiveListener(interface="lo", timeout=1)
        # CIP Identity Object class 0x01, instance 1, attribute 16 (decimal in EK).
        layer = _FakeLayer(**{"class": "16", "instance": "1", "attribute": "16"})
        cip_class = listener._parse_int(listener.get_field(layer, "class", None), None)
        instance = listener._parse_int(listener.get_field(layer, "instance", None), None)
        attribute = listener._parse_int(listener.get_field(layer, "attribute", None), None)
        assert cip_class == 16, "EK decimal 16 must parse as 16, not hex 0x16=22"
        assert instance == 1
        assert attribute == 16

    def test_can_id_ek_decimal_not_reparsed_as_hex(self):
        from oida.pcap.devicenet import DeviceNetPassiveListener

        listener = DeviceNetPassiveListener(interface="lo", timeout=1)
        # CAN id 0x3FF renders as decimal "1023" in EK mode.
        layer = _FakeLayer(can_id="1023")
        can_id = listener._parse_int(listener.get_field(layer, "can_id", None), None)
        assert can_id == 1023, "EK decimal 1023 must parse as 1023, not hex 0x1023=4131"
        assert can_id == 0x3FF

    def test_source_no_longer_forces_base16(self):
        import inspect

        import oida.pcap.devicenet as mod

        assert "base=16" not in inspect.getsource(mod), "base=16 must not be reintroduced"
