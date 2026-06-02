"""Smoke tests for the hl7 passive listener.

No reference pcap is bundled for hl7 yet; these tests verify the
listener module loads cleanly, the class is importable, the
REQUIRED_LAYERS contract is set, and harvest() returns the expected
dict shape on an empty session. Once a reference pcap fixture is
added under ``tests/fixtures/pcap/hl7/`` upgrade this file to use
``_run_listener_test`` with real packet-level assertions.
"""

import pytest

pytestmark = [pytest.mark.integration]


class TestHL7PassiveSmoke:
    """hl7 listener smoke tests (no fixture pcap)."""

    def test_class_importable(self):
        import oida.pcap.passive.hl7 as mod

        cls = getattr(mod, "HL7PassiveListener", None)
        assert cls is not None, "HL7PassiveListener not exported from oida.pcap.passive.hl7"

    def test_required_layers_set(self):
        from oida.pcap.passive.hl7 import HL7PassiveListener

        required = getattr(HL7PassiveListener, "REQUIRED_LAYERS", None)
        assert required, "REQUIRED_LAYERS must be set so the listener registers a filter"
        assert "hl7" in required or len(required) > 0

    def test_harvest_shape_on_empty(self):
        from oida.pcap.passive.hl7 import HL7PassiveListener

        listener = HL7PassiveListener(interface="lo", timeout=1)
        listener._x509 = True
        result = listener.harvest()
        assert isinstance(result, dict), "harvest() must return a dict"
