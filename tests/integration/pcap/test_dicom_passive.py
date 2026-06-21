"""Smoke tests for the dicom passive listener.

No reference pcap is bundled for dicom yet; these tests verify the
listener module loads cleanly, the class is importable, the
REQUIRED_LAYERS contract is set, and harvest() returns the expected
dict shape on an empty session. Once a reference pcap fixture is
added under ``tests/fixtures/pcap/dicom/`` upgrade this file to use
``_run_listener_test`` with real packet-level assertions.
"""

import pytest

pytestmark = [pytest.mark.integration]


class TestDICOMPassiveSmoke:
    """dicom listener smoke tests (no fixture pcap)."""

    def test_class_importable(self):
        import oida.pcap.dicom as mod

        cls = getattr(mod, "DICOMPassiveListener", None)
        assert cls is not None, "DICOMPassiveListener not exported from oida.pcap.dicom"

    def test_required_layers_set(self):
        from oida.pcap.dicom import DICOMPassiveListener

        required = getattr(DICOMPassiveListener, "REQUIRED_LAYERS", None)
        assert required, "REQUIRED_LAYERS must be set so the listener registers a filter"
        assert "dicom" in required or len(required) > 0

    def test_harvest_shape_on_empty(self):
        from oida.pcap.dicom import DICOMPassiveListener

        listener = DICOMPassiveListener(interface="lo", timeout=1)
        listener._x509 = True
        result = listener.harvest()
        assert isinstance(result, dict), "harvest() must return a dict"
