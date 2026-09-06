"""Smoke tests for the canopen passive listener.

No reference pcap is bundled for canopen yet; these tests verify the
listener module loads cleanly, the class is importable, the
REQUIRED_LAYERS contract is set, and harvest() returns the expected
dict shape on an empty session. Once a reference pcap fixture is
added under ``tests/fixtures/pcap/canopen/`` upgrade this file to use
``_run_listener_test`` with real packet-level assertions.
"""

import pytest

pytestmark = [pytest.mark.integration]


class TestCANopenPassiveSmoke:
    """canopen listener smoke tests (no fixture pcap)."""

    def test_class_importable(self):
        import oida.pcap.canopen as mod

        cls = getattr(mod, "CANopenPassiveListener", None)
        assert cls is not None, "CANopenPassiveListener not exported from oida.pcap.canopen"

    def test_required_layers_set(self):
        from oida.pcap.canopen import CANopenPassiveListener

        required = getattr(CANopenPassiveListener, "REQUIRED_LAYERS", None)
        assert required, "REQUIRED_LAYERS must be set so the listener registers a filter"
        assert "canopen" in required or len(required) > 0

    def test_harvest_shape_on_empty(self):
        from oida.pcap.canopen import CANopenPassiveListener

        listener = CANopenPassiveListener(interface="lo", timeout=1)
        listener._x509 = True
        result = listener.harvest()
        assert isinstance(result, dict), "harvest() must return a dict"


class _FakeLayer:
    """Minimal stand-in for a pyshark layer (attribute -> value)."""

    def __init__(self, **fields):
        for k, v in fields.items():
            setattr(self, k, v)


class TestCANopenEKDecimalParsing:
    """Regression: EK-mode BASE_HEX fields arrive as DECIMAL strings.

    In FileCapture(use_ek=True) tshark renders BASE_HEX integers as their
    decimal value (e.g. OD index 0x1018 -> "4120"). Forcing base=16 on those
    reparsed "4120" as hex 0x4120=16672. The fix drops base=16, so the value
    must round-trip as its true decimal magnitude.
    """

    def test_sdo_index_ek_decimal_not_reparsed_as_hex(self):
        from oida.pcap.canopen import CANopenPassiveListener

        listener = CANopenPassiveListener(interface="lo", timeout=1)
        # EK mode delivers "4120" (decimal) for OD index 0x1018, "2" for subidx.
        layer = _FakeLayer(sdo_main_idx="4120", sdo_sub_idx="2")
        main_idx = listener._parse_int(listener.get_field(layer, "sdo_main_idx"), None)
        sub_idx = listener._parse_int(listener.get_field(layer, "sdo_sub_idx"), None)
        assert main_idx == 4120, "EK decimal 4120 must parse as 4120, not hex 0x4120=16672"
        assert main_idx == 0x1018
        assert sub_idx == 2

    def test_nmt_state_ek_decimal_not_reparsed_as_hex(self):
        from oida.pcap.canopen import CANopenPassiveListener

        listener = CANopenPassiveListener(interface="lo", timeout=1)
        # NMT state 0xFD (Pre-operational) renders as decimal "253" in EK mode.
        layer = _FakeLayer(nmt_guard_state="253")
        state = listener._parse_int(listener.get_field(layer, "nmt_guard_state"), 0)
        assert state == 253, "EK decimal 253 must parse as 253, not hex 0x253=595"

    def test_source_no_longer_forces_base16(self):
        import inspect

        import oida.pcap.canopen as mod

        assert "base=16" not in inspect.getsource(mod), "base=16 must not be reintroduced"
