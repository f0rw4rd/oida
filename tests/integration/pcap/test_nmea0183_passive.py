"""Smoke tests for the nmea0183 passive listener.

No reference pcap is bundled for nmea0183 yet; these tests verify the
listener module loads cleanly, the class is importable, the
REQUIRED_LAYERS contract is set, and harvest() returns the expected
dict shape on an empty session. Once a reference pcap fixture is
added under ``tests/fixtures/pcap/nmea0183/`` upgrade this file to use
``_run_listener_test`` with real packet-level assertions.
"""

import pytest

pytestmark = [pytest.mark.integration]


class TestNMEA0183PassiveSmoke:
    """nmea0183 listener smoke tests (no fixture pcap)."""

    def test_class_importable(self):
        import oida.pcap.passive.nmea0183 as mod

        cls = getattr(mod, "NMEA0183PassiveListener", None)
        assert cls is not None, "NMEA0183PassiveListener not exported from oida.pcap.passive.nmea0183"

    def test_required_layers_set(self):
        from oida.pcap.passive.nmea0183 import NMEA0183PassiveListener

        required = getattr(NMEA0183PassiveListener, "REQUIRED_LAYERS", None)
        assert required, "REQUIRED_LAYERS must be set so the listener registers a filter"
        assert "nmea0183" in required or len(required) > 0

    def test_harvest_shape_on_empty(self):
        from oida.pcap.passive.nmea0183 import NMEA0183PassiveListener

        listener = NMEA0183PassiveListener(interface="lo", timeout=1)
        listener._x509 = True
        result = listener.harvest()
        assert isinstance(result, dict), "harvest() must return a dict"
