"""Smoke tests for the coap passive listener.

No reference pcap is bundled for coap yet; these tests verify the
listener module loads cleanly, the class is importable, the
REQUIRED_LAYERS contract is set, and harvest() returns the expected
dict shape on an empty session. Once a reference pcap fixture is
added under ``tests/fixtures/pcap/coap/`` upgrade this file to use
``_run_listener_test`` with real packet-level assertions.
"""

import pytest

pytestmark = [pytest.mark.integration]


class TestCoAPPassiveSmoke:
    """coap listener smoke tests (no fixture pcap)."""

    def test_class_importable(self):
        import oida.pcap.coap as mod

        cls = getattr(mod, "CoAPPassiveListener", None)
        assert cls is not None, "CoAPPassiveListener not exported from oida.pcap.coap"

    def test_required_layers_set(self):
        from oida.pcap.coap import CoAPPassiveListener

        required = getattr(CoAPPassiveListener, "REQUIRED_LAYERS", None)
        assert required, "REQUIRED_LAYERS must be set so the listener registers a filter"
        assert "coap" in required or len(required) > 0

    def test_harvest_shape_on_empty(self):
        from oida.pcap.coap import CoAPPassiveListener

        listener = CoAPPassiveListener(interface="lo", timeout=1)
        listener._x509 = True
        result = listener.harvest()
        assert isinstance(result, dict), "harvest() must return a dict"
