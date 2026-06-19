"""Smoke tests for the epl passive listener.

No reference pcap is bundled for epl yet; these tests verify the
listener module loads cleanly, the class is importable, the
REQUIRED_LAYERS contract is set, and harvest() returns the expected
dict shape on an empty session. Once a reference pcap fixture is
added under ``tests/fixtures/pcap/epl/`` upgrade this file to use
``_run_listener_test`` with real packet-level assertions.
"""

import pytest

pytestmark = [pytest.mark.integration]


class TestEPLPassiveSmoke:
    """epl listener smoke tests (no fixture pcap)."""

    def test_class_importable(self):
        import oida.pcap.passive.epl as mod

        cls = getattr(mod, "EPLPassiveListener", None)
        assert cls is not None, "EPLPassiveListener not exported from oida.pcap.passive.epl"

    def test_required_layers_set(self):
        from oida.pcap.passive.epl import EPLPassiveListener

        required = getattr(EPLPassiveListener, "REQUIRED_LAYERS", None)
        assert required, "REQUIRED_LAYERS must be set so the listener registers a filter"
        assert "epl" in required or len(required) > 0

    def test_harvest_shape_on_empty(self):
        from oida.pcap.passive.epl import EPLPassiveListener

        listener = EPLPassiveListener(interface="lo", timeout=1)
        listener._x509 = True
        result = listener.harvest()
        assert isinstance(result, dict), "harvest() must return a dict"


class _FakeLayer:
    """Minimal stand-in for a pyshark layer (attribute -> value)."""

    def __init__(self, **fields):
        for k, v in fields.items():
            setattr(self, k, v)


class TestEPLEKDecimalParsing:
    """Regression: EK-mode BASE_HEX fields arrive as DECIMAL strings.

    Forcing base=16 reparsed an EK decimal like "4120" as hex 0x4120=16672.
    The fix drops base=16 so values round-trip at their true magnitude.
    """

    def test_sdo_index_ek_decimal_not_reparsed_as_hex(self):
        from oida.pcap.passive.epl import EPLPassiveListener

        listener = EPLPassiveListener(interface="lo", timeout=1)
        # asnd_sdo_cmd_data_index 0x1018 renders as decimal "4120" in EK mode.
        layer = _FakeLayer(asnd_sdo_cmd_data_index="4120")
        index_val = listener._parse_int(
            listener.get_field(layer, "asnd_sdo_cmd_data_index"), None
        )
        assert index_val == 4120, "EK decimal 4120 must parse as 4120, not hex 0x4120=16672"
        assert index_val == 0x1018

    def test_nmt_command_ek_decimal_not_reparsed_as_hex(self):
        from oida.pcap.passive.epl import EPLPassiveListener

        listener = EPLPassiveListener(interface="lo", timeout=1)
        # NMT command id 0x2C (Stop Node) renders as decimal "44" in EK mode.
        layer = _FakeLayer(cmd_id="44")
        cmd_id = listener._parse_int(listener.get_field(layer, "cmd_id"), None)
        assert cmd_id == 44, "EK decimal 44 must parse as 44, not hex 0x44=68"

    def test_source_no_longer_forces_base16(self):
        import inspect

        import oida.pcap.passive.epl as mod

        assert "base=16" not in inspect.getsource(mod), "base=16 must not be reintroduced"
