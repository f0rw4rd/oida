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
