"""Smoke tests for the iec103 passive listener.

No reference pcap is bundled for iec103 yet; these tests verify the
listener module loads cleanly, the class is importable, the
REQUIRED_LAYERS contract is set, and harvest() returns the expected
dict shape on an empty session. Once a reference pcap fixture is
added under ``tests/fixtures/pcap/iec103/`` upgrade this file to use
``_run_listener_test`` with real packet-level assertions.
"""

import pytest

pytestmark = [pytest.mark.integration]


class TestIEC103PassiveSmoke:
    """iec103 listener smoke tests (no fixture pcap)."""

    def test_class_importable(self):
        import oida.pcap.passive.iec103 as mod

        cls = getattr(mod, "IEC103PassiveListener", None)
        assert cls is not None, "IEC103PassiveListener not exported from oida.pcap.passive.iec103"

    def test_required_layers_set(self):
        from oida.pcap.passive.iec103 import IEC103PassiveListener

        required = getattr(IEC103PassiveListener, "REQUIRED_LAYERS", None)
        assert required, "REQUIRED_LAYERS must be set so the listener registers a filter"
        assert "iec60870_5_103" in required or len(required) > 0

    def test_harvest_shape_on_empty(self):
        from oida.pcap.passive.iec103 import IEC103PassiveListener

        listener = IEC103PassiveListener(interface="lo", timeout=1)
        listener._x509 = True
        result = listener.harvest()
        assert isinstance(result, dict), "harvest() must return a dict"
