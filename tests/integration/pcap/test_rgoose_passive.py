"""Smoke tests for the rgoose passive listener.

No reference pcap is bundled for rgoose yet; these tests verify the
listener module loads cleanly, the class is importable, the
REQUIRED_LAYERS contract is set, and harvest() returns the expected
dict shape on an empty session. Once a reference pcap fixture is
added under ``tests/fixtures/pcap/rgoose/`` upgrade this file to use
``_run_listener_test`` with real packet-level assertions.
"""

import pytest

pytestmark = [pytest.mark.integration]


class TestRGOOSEPassiveSmoke:
    """rgoose listener smoke tests (no fixture pcap)."""

    def test_class_importable(self):
        import oida.pcap.rgoose as mod

        cls = getattr(mod, "RGOOSEPassiveListener", None)
        assert cls is not None, "RGOOSEPassiveListener not exported from oida.pcap.rgoose"

    def test_required_layers_set(self):
        from oida.pcap.rgoose import RGOOSEPassiveListener

        required = getattr(RGOOSEPassiveListener, "REQUIRED_LAYERS", None)
        assert required, "REQUIRED_LAYERS must be set so the listener registers a filter"
        assert "goose" in required or len(required) > 0

    def test_harvest_shape_on_empty(self):
        from oida.pcap.rgoose import RGOOSEPassiveListener

        listener = RGOOSEPassiveListener(interface="lo", timeout=1)
        listener._x509 = True
        result = listener.harvest()
        assert isinstance(result, dict), "harvest() must return a dict"

    def test_l2_goose_without_ip_dropped_with_debug_log(self):
        """A 'goose' packet with no IP (L2 GOOSE) must be dropped, not recorded,
        and the drop must emit a debug trace rather than vanishing silently.
        """
        from unittest.mock import MagicMock

        from oida.pcap.rgoose import RGOOSEPassiveListener

        listener = RGOOSEPassiveListener(interface="lo", timeout=1)
        listener.logger = MagicMock()

        # Fake an L2 GOOSE packet: has a 'goose' layer but get_ip_info yields no IP.
        packet = MagicMock()
        packet.goose = MagicMock()
        listener.get_ip_info = MagicMock(return_value=(None, None))

        listener.process_packet(packet)

        # No publisher/device created from a no-IP packet, and a debug log was emitted.
        assert listener.publishers == {}, "L2 GOOSE (no IP) must not create a publisher"
        assert listener.logger.debug.called, "no-IP drop must emit a debug trace"
