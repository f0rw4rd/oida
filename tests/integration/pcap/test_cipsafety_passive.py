"""Smoke tests for the cipsafety passive listener.

No reference pcap is bundled for cipsafety yet; these tests verify the
listener module loads cleanly, the class is importable, the
REQUIRED_LAYERS contract is set, and harvest() returns the expected
dict shape on an empty session. Once a reference pcap fixture is
added under ``tests/fixtures/pcap/cipsafety/`` upgrade this file to use
``_run_listener_test`` with real packet-level assertions.
"""

import pytest

pytestmark = [pytest.mark.integration]


class TestCIPSafetyPassiveSmoke:
    """cipsafety listener smoke tests (no fixture pcap)."""

    def test_class_importable(self):
        import oida.pcap.passive.cipsafety as mod

        cls = getattr(mod, "CIPSafetyPassiveListener", None)
        assert cls is not None, "CIPSafetyPassiveListener not exported from oida.pcap.passive.cipsafety"

    def test_required_layers_set(self):
        from oida.pcap.passive.cipsafety import CIPSafetyPassiveListener

        required = getattr(CIPSafetyPassiveListener, "REQUIRED_LAYERS", None)
        assert required, "REQUIRED_LAYERS must be set so the listener registers a filter"
        assert "cipsafety" in required or len(required) > 0

    def test_harvest_shape_on_empty(self):
        from oida.pcap.passive.cipsafety import CIPSafetyPassiveListener

        listener = CIPSafetyPassiveListener(interface="lo", timeout=1)
        listener._x509 = True
        result = listener.harvest()
        assert isinstance(result, dict), "harvest() must return a dict"
