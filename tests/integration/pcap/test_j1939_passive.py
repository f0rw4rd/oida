"""Smoke tests for the j1939 passive listener.

No reference pcap is bundled for j1939 yet; these tests verify the
listener module loads cleanly, the class is importable, the
REQUIRED_LAYERS contract is set, and harvest() returns the expected
dict shape on an empty session. Once a reference pcap fixture is
added under ``tests/fixtures/pcap/j1939/`` upgrade this file to use
``_run_listener_test`` with real packet-level assertions.
"""

import pytest

pytestmark = [pytest.mark.integration]


class TestJ1939PassiveSmoke:
    """j1939 listener smoke tests (no fixture pcap)."""

    def test_class_importable(self):
        import oida.pcap.passive.j1939 as mod

        cls = getattr(mod, "J1939PassiveListener", None)
        assert cls is not None, "J1939PassiveListener not exported from oida.pcap.passive.j1939"

    def test_required_layers_set(self):
        from oida.pcap.passive.j1939 import J1939PassiveListener

        required = getattr(J1939PassiveListener, "REQUIRED_LAYERS", None)
        assert required, "REQUIRED_LAYERS must be set so the listener registers a filter"
        assert "j1939" in required or len(required) > 0

    def test_harvest_shape_on_empty(self):
        from oida.pcap.passive.j1939 import J1939PassiveListener

        listener = J1939PassiveListener(interface="lo", timeout=1)
        listener._x509 = True
        result = listener.harvest()
        assert isinstance(result, dict), "harvest() must return a dict"
