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
        import oida.pcap.sercos as mod

        cls = getattr(mod, "SERCOSPassiveListener", None)
        assert cls is not None, "SERCOSPassiveListener not exported from oida.pcap.sercos"

    def test_required_layers_set(self):
        from oida.pcap.sercos import SERCOSPassiveListener

        required = getattr(SERCOSPassiveListener, "REQUIRED_LAYERS", None)
        assert required, "REQUIRED_LAYERS must be set so the listener registers a filter"
        assert "siii" in required or len(required) > 0

    def test_harvest_shape_on_empty(self):
        from oida.pcap.sercos import SERCOSPassiveListener

        listener = SERCOSPassiveListener(interface="lo", timeout=1)
        listener._x509 = True
        result = listener.harvest()
        assert isinstance(result, dict), "harvest() must return a dict"


class _FakeLayer:
    """Minimal stand-in for a pyshark layer (attribute -> value)."""

    def __init__(self, **fields):
        for k, v in fields.items():
            setattr(self, k, v)


class TestSERCOSEKDecimalParsing:
    """Regression: EK-mode BASE_HEX fields arrive as DECIMAL strings.

    Forcing base=16 reparsed an EK decimal like "4120" as hex 0x4120=16672.
    The fix drops base=16 so values round-trip at their true magnitude.
    """

    def test_idn_ek_decimal_not_reparsed_as_hex(self):
        from oida.pcap.sercos import SERCOSPassiveListener

        listener = SERCOSPassiveListener(interface="lo", timeout=1)
        # IDN S-0-0032 packs to 0x0020 -> renders as decimal "32" in EK mode.
        layer = _FakeLayer(mdt_svch_idn="32")
        idn_val = listener._parse_int(listener.get_field(layer, "mdt_svch_idn"), None)
        assert idn_val == 32, "EK decimal 32 must parse as 32, not hex 0x32=50"

    def test_phase_ek_decimal_not_reparsed_as_hex(self):
        from oida.pcap.sercos import SERCOSPassiveListener

        listener = SERCOSPassiveListener(interface="lo", timeout=1)
        # Communication phase fields render as plain decimal in EK mode.
        layer = _FakeLayer(mst_phase="16")
        phase = listener._parse_int(listener.get_field(layer, "mst_phase"), None)
        assert phase == 16, "EK decimal 16 must parse as 16, not hex 0x16=22"

    def test_source_no_longer_forces_base16(self):
        import inspect

        import oida.pcap.sercos as mod

        assert "base=16" not in inspect.getsource(mod), "base=16 must not be reintroduced"


class TestSERCOSSvcAttribution:
    """Regression: SVC read/write counts must land on the addressed slave.

    The old code iterated self.slaves.values() and credited the FIRST slave
    in dict order, mis-assigning SVC activity in any multi-slave ring. The
    fix attributes SVC stats to the slave addressed by the telegram.
    """

    def _listener_with_two_slaves(self):
        from oida.pcap.sercos import SERCOSPassiveListener

        listener = SERCOSPassiveListener(interface="lo", timeout=1)
        # Insertion order matters: slave 1 is first in dict order.
        listener._ensure_slave(1, "t0")
        listener._ensure_slave(2, "t0")
        return listener

    def test_svc_write_credited_to_addressed_slave(self):
        listener = self._listener_with_two_slaves()
        # SVC write addressed to slave 2 (NOT the first-in-dict slave 1).
        layer = _FakeLayer(mdt_svch_rw="1", mdt_svch_idn="32")
        listener._process_svc(layer, "t1", target_addr=2)

        assert listener.slaves[2].svc_write_count == 1
        assert listener.slaves[1].svc_write_count == 0, "first-in-dict slave must not be credited"
        assert "S-0-0032" in listener.slaves[2].idns_accessed
        assert listener.slaves[1].idns_accessed == set()

    def test_svc_read_credited_to_addressed_slave(self):
        listener = self._listener_with_two_slaves()
        layer = _FakeLayer(mdt_svch_rw="0", mdt_svch_idn="32")
        listener._process_svc(layer, "t1", target_addr=2)

        assert listener.slaves[2].svc_read_count == 1
        assert listener.slaves[1].svc_read_count == 0, "first-in-dict slave must not be credited"

    def test_svc_no_target_addr_credits_nobody(self):
        listener = self._listener_with_two_slaves()
        # With MULTIPLE slaves and no addressed slave, attribution is ambiguous
        # so SVC stats must not be mis-attributed to any of them.
        layer = _FakeLayer(mdt_svch_rw="1", mdt_svch_idn="32")
        listener._process_svc(layer, "t1", target_addr=None)

        assert listener.slaves[1].svc_write_count == 0
        assert listener.slaves[2].svc_write_count == 0

    def test_svc_no_target_addr_single_slave_credited(self):
        # Regression: the SVC channel lives in the MDT (slot-addressed), so
        # target_addr is usually None here. On a single-slave bus the attribution
        # is unambiguous and must still be recorded — crediting nobody (an earlier
        # over-correction) silently lost all SVC read/write counts.
        from oida.pcap.sercos import SERCOSPassiveListener

        listener = SERCOSPassiveListener(interface="lo", timeout=1)
        listener._ensure_slave(7, "t0")
        layer = _FakeLayer(mdt_svch_rw="1", mdt_svch_idn="32")
        listener._process_svc(layer, "t1", target_addr=None)

        assert listener.slaves[7].svc_write_count == 1
        assert "S-0-0032" in listener.slaves[7].idns_accessed
