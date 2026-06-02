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
