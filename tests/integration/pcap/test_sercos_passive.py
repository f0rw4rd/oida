"""Smoke tests for the sercos passive listener.

No reference pcap is bundled for sercos yet; these tests verify the
listener module loads cleanly, the class is importable, the
REQUIRED_LAYERS contract is set, and harvest() returns the expected
dict shape on an empty session. Once a reference pcap fixture is
added under ``tests/fixtures/pcap/sercos/`` upgrade this file to use
``_run_listener_test`` with real packet-level assertions.
"""

import pytest

pytestmark = [pytest.mark.integration]


class TestSERCOSPassiveSmoke:
    """sercos listener smoke tests (no fixture pcap)."""

    def test_class_importable(self):
        import oida.pcap.passive.sercos as mod

        cls = getattr(mod, "SERCOSPassiveListener", None)
        assert cls is not None, "SERCOSPassiveListener not exported from oida.pcap.passive.sercos"

    def test_required_layers_set(self):
        from oida.pcap.passive.sercos import SERCOSPassiveListener

        required = getattr(SERCOSPassiveListener, "REQUIRED_LAYERS", None)
        assert required, "REQUIRED_LAYERS must be set so the listener registers a filter"
        assert "siii" in required or len(required) > 0

    def test_harvest_shape_on_empty(self):
        from oida.pcap.passive.sercos import SERCOSPassiveListener

        listener = SERCOSPassiveListener(interface="lo", timeout=1)
        listener._x509 = True
        result = listener.harvest()
        assert isinstance(result, dict), "harvest() must return a dict"


class _FakeLayer:
    """Minimal stand-in for a pyshark layer (attribute -> value)."""

    def __init__(self, **fields):
        for k, v in fields.items():
            setattr(self, k, v)


class TestSERCOSEKDecimalParsing:
    """Regression: EK-mode BASE_HEX fields arrive as DECIMAL strings.

    Forcing base=16 reparsed an EK decimal like "4120" as hex 0x4120=16672.
    The fix drops base=16 so values round-trip at their true magnitude.
    """

    def test_idn_ek_decimal_not_reparsed_as_hex(self):
        from oida.pcap.passive.sercos import SERCOSPassiveListener

        listener = SERCOSPassiveListener(interface="lo", timeout=1)
        # IDN S-0-0032 packs to 0x0020 -> renders as decimal "32" in EK mode.
        layer = _FakeLayer(mdt_svch_idn="32")
        idn_val = listener._parse_int(listener.get_field(layer, "mdt_svch_idn"), None)
        assert idn_val == 32, "EK decimal 32 must parse as 32, not hex 0x32=50"

    def test_phase_ek_decimal_not_reparsed_as_hex(self):
        from oida.pcap.passive.sercos import SERCOSPassiveListener

        listener = SERCOSPassiveListener(interface="lo", timeout=1)
        # Communication phase fields render as plain decimal in EK mode.
        layer = _FakeLayer(mst_phase="16")
        phase = listener._parse_int(listener.get_field(layer, "mst_phase"), None)
        assert phase == 16, "EK decimal 16 must parse as 16, not hex 0x16=22"

    def test_source_no_longer_forces_base16(self):
        import inspect

        import oida.pcap.passive.sercos as mod

        assert "base=16" not in inspect.getsource(mod), "base=16 must not be reintroduced"
